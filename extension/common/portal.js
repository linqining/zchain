// =============================================================================
// extension/common/portal.js — proof portal 客户端逻辑（Extension 0.2 → 0.4/stwo-wasm）
//
// "验证一手牌"的扩展侧（E3 的扩展部分）：
//   hand binding → GET {gateway}/api/v1/settlement/{binding}（明细：payout_root、
//   rake、层级 proven/soft_accepted）→ GET {gateway}/api/v1/proof/{binding}
//   （归档元数据 + payload_b64 + X-Zchain-Engine）→ **STARK wasm 完整验证**
//   （0.4 起：canonical 归档字节直接在浏览器内跑 stwo 验证器，见 verifyStarkProof）
//   → wallet-core wasm `wallet_verify_settlement_detail` 本地复验结算关系 →
//   展示 verifier 版本 / 耗时 / 结论。
//
// 诚实边界（不虚标）：
// - 结算关系复验全部在 wallet-core wasm（payout_root 复算 + 守恒 + 费率关系）；
//   STARK 证明本体自 0.4 起由 vendor/stwo-verify 的 wasm 验证器在本地完整验证
//   （FRI + Merkle + 约束 + 公开 scope 承诺重建），verifier 版本与耗时如实展示；
//   wasm 加载失败时 STARK 阶段如实报 StarkVerifierError，绝不伪造结论；
// - 网关不可达/未配置/404/超时全部如实报错（GatewayNotConfigured /
//   GatewayUnreachable / GatewayTimeout / SettlementNotFound / ProofNotFound）；
// - 层级（proven / soft_accepted）是网关水位声明，portal 原样展示、不推进。
//
// 纯函数 + 注入式 fetch：零浏览器全局（node --test 用注入 fetch 覆盖）。
// =============================================================================

import { validateHex } from './validation.js';

/** fetch 超时（ms）；AbortError 归类为 GatewayTimeout（与网络层失败分开如实呈现）。 */
const DEFAULT_FETCH_TIMEOUT_MS = 15_000;

/** hand binding 解析：接受 0x 前缀/大小写；必须 32 字节 hex。 */
export function parseBinding(input) {
  if (typeof input !== 'string') {
    return { ok: false, code: 'BadBinding', reason: 'binding must be a hex string' };
  }
  const raw = input.trim().replace(/^0x/, '').toLowerCase();
  const check = validateHex(raw, 32);
  if (!check.ok) {
    return { ok: false, code: 'BadBinding', reason: 'binding must be 64 hex chars (32 bytes)' };
  }
  return { ok: true, binding: raw };
}

/** 网关 base URL → 端点 URL（gateway 必须是 scheme://host:port 形状）。 */
export function settlementUrl(gateway, binding) {
  return `${gateway}/api/v1/settlement/${binding}`;
}

export function proofUrl(gateway, binding) {
  return `${gateway}/api/v1/proof/${binding}`;
}

/** 网关 status 端点（TE-M5：资产摘要对账面）。 */
export function statusUrl(gateway) {
  return `${gateway}/api/v1/status`;
}

/**
 * 拉取网关资产摘要（TE-M5：REAL 域三 token + GAME 域注册表/供给对账）。
 *
 * replay 模式网关返回 `assets` 对象；index 模式/旧网关 `assets` 为
 * null——形状校验 fail-closed 返回 BadShape（如实呈现"不可得"，不伪造
 * 空注册表）。错误分类与 fetchSettlement 一致。
 */
export async function fetchAssetSummary(gateway, fetchImpl = fetch, timeoutMs = DEFAULT_FETCH_TIMEOUT_MS) {
  if (!gateway) {
    return { ok: false, code: 'GatewayNotConfigured', reason: '当前网络未配置网关 URL（在下方设置）' };
  }
  let res;
  try {
    res = await fetchImpl(statusUrl(gateway), { method: 'GET', signal: timeoutSignal(timeoutMs) });
  } catch (e) {
    return { ok: false, ...classifyFetchError(e, null, 'status') };
  }
  if (!res.ok) {
    return { ok: false, ...classifyFetchError(null, res.status, 'status') };
  }
  let body;
  try {
    body = await res.json();
  } catch {
    return { ok: false, code: 'GatewayHttpError', reason: 'gateway returned non-JSON body' };
  }
  const assets = body?.assets;
  if (!assets || typeof assets !== 'object' || !assets.game || !Array.isArray(assets.game.tokens)) {
    return { ok: false, code: 'BadShape', reason: 'gateway status has no asset summary (index mode or gateway without TE-M5 fields)' };
  }
  return { ok: true, assets };
}

/**
 * 网关可达性错误分类（fail-closed 命名）：
 * - GatewayNotConfigured：该网络没有可用网关 URL（如 testnet 未部署）；
 * - GatewayUnreachable：fetch 网络层失败（含 CORS 拒绝——浏览器侧无法区分，
 *   如实给同一个码 + 排查提示）；
 * - GatewayHttpError：网关在但返回非 200/404 的状态（429/5xx）；
 * - SettlementNotFound / ProofNotFound：格式合法但不存在（网关 404）。
 */
export function classifyFetchError(err, status, kind) {
  if (err) {
    if (err?.name === 'AbortError') {
      return {
        code: 'GatewayTimeout',
        reason: `网关超时（超过 fetch 超时上限未响应）。网关可能过载或网络异常；STARK 归档较大（MB 级），慢链路下可重试。`,
      };
    }
    return {
      code: 'GatewayUnreachable',
      reason: `网关不可达（网络层失败或 CORS 拒绝）：${String(err?.message ?? err)}。请确认网关已启动；跨源访问需要网关以 --public 启动或已授予主机权限。`,
    };
  }
  if (status === 404) {
    const code = kind === 'proof' ? 'ProofNotFound' : kind === 'settlement' ? 'SettlementNotFound' : 'NotFound';
    return { code, reason: `gateway 404: not found` };
  }
  if (status === 400) {
    return { code: 'BadBinding', reason: 'gateway 400: 参数被网关拒绝（binding 形状非法）' };
  }
  return { code: 'GatewayHttpError', reason: `gateway HTTP ${status}` };
}

/**
 * 拉取结算明细（带超时；默认 15s，AbortError → GatewayTimeout）。
 * @returns {ok:true, detail} | {ok:false, code, reason}
 */
export async function fetchSettlement(gateway, binding, fetchImpl = fetch, timeoutMs = DEFAULT_FETCH_TIMEOUT_MS) {
  if (!gateway) {
    return { ok: false, code: 'GatewayNotConfigured', reason: '当前网络未配置网关 URL（在下方设置）' };
  }
  let res;
  try {
    res = await fetchImpl(settlementUrl(gateway, binding), { method: 'GET', signal: timeoutSignal(timeoutMs) });
  } catch (e) {
    return { ok: false, ...classifyFetchError(e, null, 'settlement') };
  }
  if (!res.ok) {
    return { ok: false, ...classifyFetchError(null, res.status, 'settlement') };
  }
  let detail;
  try {
    detail = await res.json();
  } catch {
    return { ok: false, code: 'GatewayHttpError', reason: 'gateway returned non-JSON body' };
  }
  if (!detail || typeof detail !== 'object' || typeof detail.hand_binding !== 'string') {
    return { ok: false, code: 'GatewayHttpError', reason: 'gateway response is not a settlement detail' };
  }
  return { ok: true, detail };
}

/**
 * 拉取 proof 归档（元数据 + payload_b64 本体——0.4 起 STARK wasm 验证需要归档
 * 字节；engine 优先取响应体字段，跨源下 X-Zchain-Engine 头仅在已授予主机权限
 * 时可读，读到则以响应头为准）。
 */
/** 可验证归档体积上限（R-20）。5 MB 是 PRD 建议值，需评审确认。 */
export const MAX_PROOF_BYTES = 5 * 1024 * 1024;

export async function fetchProof(gateway, binding, fetchImpl = fetch, timeoutMs = DEFAULT_FETCH_TIMEOUT_MS) {
  if (!gateway) {
    return { ok: false, code: 'GatewayNotConfigured', reason: '当前网络未配置网关 URL（在下方设置）' };
  }
  let res;
  try {
    res = await fetchImpl(proofUrl(gateway, binding), { method: 'GET', signal: timeoutSignal(timeoutMs) });
  } catch (e) {
    return { ok: false, ...classifyFetchError(e, null, 'proof') };
  }
  if (!res.ok) {
    return { ok: false, ...classifyFetchError(null, res.status, 'proof') };
  }
  let body;
  try {
    body = await res.json();
  } catch {
    return { ok: false, code: 'GatewayHttpError', reason: 'gateway returned non-JSON body' };
  }
  if (typeof body.payload_b64 !== 'string') {
    return { ok: false, code: 'GatewayHttpError', reason: 'proof payload missing' };
  }
  // R-20：网关侧只限时不限体积（`DEFAULT_FETCH_TIMEOUT_MS` 管不了大对象），
  // 而这份 payload 要在**本进程内**解码 + 送进 wasm 验证。没有上限时，一个
  // 畸形/超大归档会直接卡死 popup（380×600 的 MV3 文档没有恢复余地）。
  // base64 → 字节：`len*3/4` 减去 padding，这里按上界估算即可（宁可早拒）。
  const payloadBytes = Math.floor(body.payload_b64.length * 3 / 4);
  if (payloadBytes > MAX_PROOF_BYTES) {
    return {
      ok: false,
      code: 'ProofTooLarge',
      reason: `证明体积 ${(payloadBytes / 1024).toFixed(1)} KB 超出可验证上限 ${(MAX_PROOF_BYTES / 1024 / 1024).toFixed(1)} MB`,
      payloadBytes,
    };
  }
  // X-Zchain-Engine 响应头：跨源可读性取决于 CORS expose / 主机权限；拿得到
  // 就用头（更权威），拿不到回落响应体 engine 字段。
  const headerEngine = res.headers?.get?.('X-Zchain-Engine');
  return {
    ok: true,
    proof: {
      bindingHex: typeof body.binding_hex === 'string' ? body.binding_hex : binding,
      opIndex: body.op_index ?? null,
      engine: headerEngine ?? body.engine ?? null,
      payloadLen: Number.isSafeInteger(body.payload_len) ? body.payload_len : body.payload_b64.length,
      engineSource: headerEngine != null ? 'header' : body.engine != null ? 'body' : 'none',
      // 0.4：payload 本体（base64）透传给 STARK wasm 验证器；解码在 verifyStarkProof。
      payloadB64: body.payload_b64,
    },
  };
}

/** 超时信号：timeoutMs 后 abort（AbortController 不存在时退化为 undefined=不限时）。 */
function timeoutSignal(timeoutMs) {
  if (!timeoutMs || typeof AbortController === 'undefined') return undefined;
  const ctrl = new AbortController();
  setTimeout(() => ctrl.abort(), timeoutMs);
  return ctrl.signal;
}

/**
 * 本地复验：调 wallet-core wasm `wallet_verify_settlement_detail`。
 * 耗时在此测量（verifier 版本/结论由 wasm 输出）。通过注入的 verify 函数
 * 调用（生产 = callCore，测试 = stub；允许异步），保持本模块零 wasm 依赖。
 *
 * @returns {Promise<{ok:true, verdict, elapsedMs}> | {ok:false, code, reason}}
 */
export async function verifyLocally(detail, verifyFn) {
  const t0 = Date.now();
  let verdict;
  try {
    verdict = await verifyFn(JSON.stringify(detail));
  } catch (e) {
    return { ok: false, code: e?.code ?? 'VerifierError', reason: String(e?.detail ?? e?.message ?? e) };
  }
  const elapsedMs = Date.now() - t0;
  if (!verdict || typeof verdict !== 'object') {
    return { ok: false, code: 'VerifierError', reason: 'verifier returned no verdict' };
  }
  return { ok: true, verdict, elapsedMs };
}

/**
 * STARK wasm 完整验证（0.4 / stwo-wasm path A）。
 *
 * 输入 canonical 归档字节（borsh ArchivedCanonicalTaggedProof，即网关
 * payload_b64 解码结果），交给注入的 starkVerifyFn 在本地 wasm 内跑完整
 * FRI + Merkle + 约束 + 公开 scope 承诺重建。本函数只做 base64 解码、
 * 耗时测量与结果分类——验证语义全部在 wasm，不在 JS 重实现。
 *
 * @param {string} payloadB64 网关 proof payload（base64 归档字节）
 * @param {(bytes: Uint8Array) => {rc:number, stats:object|null, error:string}|Promise<...>} starkVerifyFn
 *        生产 = common/stwo_verify.js 的 wasm 门面；测试 = stub。
 *        rc 语义：0=验证通过；-1=归档解码失败；-2=验证拒绝；其他=验证器内部错误。
 * @returns {Promise<{ok:true, stark:{verified:true, stats, elapsedMs, verdict:'verified'}}>
 *          | {ok:false, code:'StarkArchiveInvalid'|'StarkVerifyRejected'|'StarkVerifierError', reason, stats?, elapsedMs}>}
 */
export async function verifyStarkProof(payloadB64, starkVerifyFn) {
  if (typeof payloadB64 !== 'string' || payloadB64.length === 0) {
    return { ok: false, code: 'StarkArchiveInvalid', reason: 'proof payload 为空（网关响应缺 payload_b64）' };
  }
  let bytes;
  try {
    bytes = base64ToBytes(payloadB64);
  } catch {
    return { ok: false, code: 'StarkArchiveInvalid', reason: 'payload_b64 不是合法 base64' };
  }
  const t0 = Date.now();
  let r;
  try {
    r = await starkVerifyFn(bytes);
  } catch (e) {
    return {
      ok: false,
      code: 'StarkVerifierError',
      reason: `STARK wasm 验证器调用失败：${String(e?.message ?? e)}`,
      elapsedMs: Date.now() - t0,
    };
  }
  const elapsedMs = Date.now() - t0;
  if (!r || typeof r.rc !== 'number') {
    return { ok: false, code: 'StarkVerifierError', reason: 'STARK 验证器未返回 rc', elapsedMs };
  }
  if (r.rc === 0) {
    return { ok: true, stark: { verified: true, verdict: 'verified', stats: r.stats ?? null, elapsedMs } };
  }
  if (r.rc === -1) {
    return { ok: false, code: 'StarkArchiveInvalid', reason: `归档无法解码（非 canonical borsh 归档）：${r.error ?? ''}`, elapsedMs };
  }
  if (r.rc === -2) {
    return { ok: false, code: 'StarkVerifyRejected', reason: `STARK 验证拒绝：${r.error ?? 'proof 不满足约束/承诺不一致'}`, stats: r.stats ?? null, elapsedMs };
  }
  return { ok: false, code: 'StarkVerifierError', reason: `STARK 验证器内部错误 rc=${r.rc}：${r.error ?? ''}`, elapsedMs };
}

/** base64 → 字节（浏览器 atob / node Buffer 双路径，零依赖）。 */
function base64ToBytes(b64) {
  if (typeof atob === 'function') {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  if (typeof Buffer === 'function') return new Uint8Array(Buffer.from(b64, 'base64'));
  throw new Error('no base64 decoder available');
}

/** 复验结论 → 展示行（检查项中文名映射；未知项原样透传）。 */
export function verdictRows(verdict) {
  const names = {
    inputs_sum_equals_pot: 'Σinputs == pot == plan.gross_pot',
    payouts_plus_rake_equals_pot: 'Σpayouts + rake == pot（守恒）',
    rake_matches_plan: 'rake.total == plan.rake',
    plan_awards_consistent: 'gross_pot − total_awards == rake',
    plan_pots_sum: 'plan 分层自洽（Σgross / Σnet+rake）',
    payout_root_recomputed: 'payout_root 本地复算一致',
    payout_table_id_consistent: 'payout table_id 与记录一致',
  };
  return (verdict?.checks ?? []).map((c) => ({
    check: c.check,
    label: names[c.check] ?? c.check,
    ok: Boolean(c.ok),
    detail: typeof c.detail === 'string' ? c.detail : '',
  }));
}
