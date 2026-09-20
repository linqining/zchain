// =============================================================================
// extension/common/telemetry.js — PRD §6.4 数据埋点（本地聚合 · 用户可关闭）
//
// 出处：docs/prd-zchain-wallet-ui-b-ledger.md §6.4（29 个事件 + 禁采清单）、
// §9「权限最小化 / 数据出域」。0.6.1 交付面**没有任何网络出口**（manifest
// host_permissions 只有 localhost / 127.0.0.1），因此本模块的实现口径是：
//
//   1. **纯本地环形缓冲 + 纯函数聚合**：零 DOM、零 IO、零 fetch。写盘与
//      「导出诊断信息」由 popup 侧决定，本模块只产出可序列化对象。
//   2. **事件 id 与属性名是封闭枚举**：未登记的事件/属性一律丢弃，
//      不做"顺手多记一个字段"。这样禁采清单可以从结构上保证，
//      而不是靠调用方自觉。
//   3. **高敏字段结构性排除**：私钥 / 助记词 / nullifier / 口令痕迹 /
//      完整地址永远进不了缓冲区。命中禁采键名 → 整条属性丢弃；
//      值形似长 hex（地址/摘要）→ 强制降级为稳定哈希引用 `r<8hex>`。
//      唯一例外：§6.4 明确允许的 `bindingPrefix`（前 8 位）与 `rawValue`
//      （阶梯词汇漂移的诊断值，本身是短标识符）。
//
// 诚实边界：本模块**不是**安全边界，只是"默认不采集"的实现约束。
// =============================================================================

/** 禁采键名（PRD §6.4 红线 + §9「数据出域」）。命中即丢弃该属性。 */
export const FORBIDDEN_KEYS = [
  'privateKey', 'privKey', 'secret', 'spendSecret', 'mnemonic', 'seed',
  'nullifier', 'password', 'passphrase', 'backupPassword', 'unlockPassword',
  'keystore', 'derivationPath', 'signature', 'sig', 'calldata', 'rawPayload',
  'sessionSecret', 'delegatedSecret',
];

const FORBIDDEN_KEY_SET = new Set(FORBIDDEN_KEYS.map((k) => k.toLowerCase()));

/** 禁采值形态：口令痕迹（`felt-poker-verifiable-9x2a` 这类 4 段连字符串）。 */
const PASSWORD_SHAPE_RE = /^[a-z0-9]{3,}-[a-z0-9]{3,}-[a-z0-9]{3,}(-[a-z0-9]{2,})?$/i;
/** 长 hex（≥24 位）一律视为地址/摘要，不落原值。 */
const LONG_HEX_RE = /^(0x)?[0-9a-f]{24,}$/i;

/** 允许保留前缀的字段（§6.4 明确列出的取值口径）。 */
const PREFIX_ALLOWED = new Set(['bindingprefix', 'rawvalue', 'code', 'reason', 'engine', 'evidence', 'fieldkind', 'screenid', 'key']);

/** 单条事件属性值长度上限（防把整个 payload 塞进埋点）。 */
const MAX_TEXT_LEN = 64;
/** 环形缓冲默认容量（超出丢最旧，与 receipts 的 MAX_RECEIPTS 同构）。 */
export const MAX_TELEMETRY_EVENTS = 500;

/**
 * 事件 schema（§6.4 表格的机器可读版本，**唯一数据源**）。
 * `props` 里的类型：
 * - `int`   计数/序号——**向下截断**（宁可少计不虚增）；
 * - `ms`    耗时读数——**四舍五入**（延迟是测量值，截断会系统性低估 p95）；
 * - `num`   其它连续量（如 payloadKB），保留 3 位小数；
 * - `bool` / `str` / `intlist` / `strlist`。
 */
export const TELEMETRY_SCHEMA = {
  popup_open: { props: { unlockedLayers: 'int', ground: 'str' } },
  screen_view: { props: { screenId: 'str', chain: 'str', tab: 'str' } },
  chain_switch: { props: { fromChain: 'str', toChain: 'str' } },
  layer_unlock: { props: { succeeded: 'intlist', failed: 'intlist', reason: 'str' } },
  amount_gate_hit: { props: { layer: 'str', available: 'str', notesNeeded: 'int' } },
  note_select_result: {
    props: {
      noteCount: 'int', hasChange: 'bool', weakest: 'str', required: 'str',
      canSubmit: 'bool', blockedReasons: 'strlist',
    },
  },
  note_count_over_limit: { props: { noteCount: 'int', limit: 'int' } },
  withdraw_preview_view: { props: { amount: 'str', reasons: 'strlist', canSubmit: 'bool' } },
  withdraw_submit_attempt_blocked: { props: { reasons: 'strlist' } },
  sign_request_resolved: { props: { decision: 'str', via: 'str', originHash: 'str', amount: 'str' } },
  session_key_exhausted: { props: { originHash: 'str', kind: 'str' } },
  session_key_revoke: { props: { originHash: 'str', confirmTyped: 'bool' } },
  proof_rail_view: { props: { weakest: 'str', required: 'str', outcome: 'str', position: 'str' } },
  proof_ladder_mismatch: { props: { rawValue: 'str' } },
  portal_verify_start: { props: { bindingPrefix: 'str', from: 'str' } },
  portal_verify_step: {
    props: {
      step: 'int', ok: 'bool', ms: 'ms', payloadKB: 'num', engine: 'str', gatewayStatus: 'str',
    },
  },
  portal_verify_result: {
    props: {
      verdict: 'str', totalMs: 'ms', overBudget: 'bool', payoutRootPresent: 'bool',
    },
  },
  receipt_state_change: {
    props: { digestHash: 'str', from: 'str', to: 'str', pastDeadline: 'bool', evidence: 'str' },
  },
  receipt_past_deadline_view: { props: { count: 'int' } },
  receipt_capacity_hit: { props: {} },
  copy_action: { props: { fieldKind: 'str', layer: 'str' } },
  qr_view_attempt: { props: { layer: 'str', qrRendered: 'bool' } },
  fiat_unavailable_view: { props: {} },
  backup_export: { props: { ok: 'bool', code: 'str', coversLayers: 'int' } },
  backup_restore_result: { props: { ok: 'bool', code: 'str', coversLayers: 'int' } },
  danger_action_confirm: { props: { action: 'str', confirmed: 'bool', frictionPassed: 'bool' } },
  rekey_partial_failure: { props: { failedLayers: 'strlist' } },
  error_shown: { props: { code: 'str', screenId: 'str' } },
  ground_switch: { props: { to: 'str' } },
  settings_change: { props: { key: 'str', from: 'str', to: 'str' } },
};

/** 交互预算 500ms（PRD §7.1 A-3 / D-55）——`overBudget` 的判定基准。 */
export const INTERACTION_BUDGET_MS = 500;

/** 事件 id 封闭枚举（未登记即 UnknownEvent，不静默记录）。 */
export function isKnownEvent(id) {
  return Object.prototype.hasOwnProperty.call(TELEMETRY_SCHEMA, id);
}

/**
 * 稳定哈希引用：把高敏原值降成不可逆的短标识，用于跨事件关联
 * （同一 origin 在 `sign_request_resolved` 与 `session_key_exhausted`
 * 里能对上一条，但不落 origin 本身）。FNV-1a 32bit，纯函数、零依赖。
 */
export function hashRef(value) {
  const s = String(value ?? '');
  if (s.length === 0) return 'r0';
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i += 1) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return `r${h.toString(16).padStart(8, '0')}`;
}

function coerce(kind, value, keyName) {
  if (value == null) return undefined;
  switch (kind) {
    case 'int': {
      const n = Number(value);
      return Number.isFinite(n) ? Math.trunc(n) : undefined;
    }
    case 'ms':
      return Number.isFinite(Number(value)) ? Math.round(Number(value)) : undefined;
    case 'num': {
      const n = Number(value);
      return Number.isFinite(n) ? Math.round(n * 1000) / 1000 : undefined;
    }
    case 'bool':
      return value === true || value === 1 || value === 'true';
    case 'intlist':
      return Array.isArray(value) ? value.map((v) => Math.trunc(Number(v) || 0)).slice(0, 8) : undefined;
    case 'strlist':
      return Array.isArray(value)
        ? value.map((v) => String(v).slice(0, MAX_TEXT_LEN)).filter((v) => v.length > 0).slice(0, 8)
        : undefined;
    case 'str':
    default: {
      let s = String(value);
      const lower = keyName.toLowerCase();
      // 名字里含 hash/ref 的值本就应是哈希；原值一律先哈希，不猜。
      if (/hash|ref$/i.test(lower) && !/^r[0-9a-f]{1,8}$/i.test(s) && !PREFIX_ALLOWED.has(lower)) {
        return hashRef(s);
      }
      if (!PREFIX_ALLOWED.has(lower)) {
        if (LONG_HEX_RE.test(s)) return hashRef(s);
        if (PASSWORD_SHAPE_RE.test(s)) return undefined; // 口令痕迹：直接丢
      }
      return s.slice(0, MAX_TEXT_LEN);
    }
  }
}

/**
 * 按 schema 清洗一次上报。
 * @returns {{ok:true, id:string, props:Record<string,unknown>, dropped:string[]}
 *          | {ok:false, code:string}}
 * `dropped` 如实带回被丢弃的键名，界面/导出可见——埋点自身也守"不静默"纪律。
 */
export function sanitizeEvent(id, attrs = {}) {
  if (!isKnownEvent(id)) return { ok: false, code: 'UnknownEvent', id: String(id ?? '') };
  const spec = TELEMETRY_SCHEMA[id];
  const props = {};
  const dropped = [];
  for (const [key, value] of Object.entries(attrs ?? {})) {
    const lower = key.toLowerCase();
    if (FORBIDDEN_KEY_SET.has(lower)) { dropped.push(key); continue; }
    const kind = spec.props[key];
    if (!kind) { dropped.push(key); continue; }
    const v = coerce(kind, value, key);
    if (v === undefined) { dropped.push(key); continue; }
    props[key] = v;
  }
  return { ok: true, id, props, dropped };
}

/**
 * 建一个遥测记录器。`enabled` 默认 false：未获用户同意不记录任何东西，
 * 关闭时 record() 是 no-op 且缓冲区不增长。
 */
export function createTelemetry({
  capacity = MAX_TELEMETRY_EVENTS,
  enabled = false,
  now = () => Date.now(),
} = {}) {
  const events = [];
  let droppedTotal = 0;
  const state = { enabled: Boolean(enabled) };

  function record(id, attrs = {}) {
    if (!state.enabled) return { ok: false, code: 'TelemetryDisabled' };
    const clean = sanitizeEvent(id, attrs);
    if (!clean.ok) { droppedTotal += 1; return clean; }
    if (clean.dropped.length > 0) droppedTotal += clean.dropped.length;
    const event = { id, at: now(), props: clean.props, dropped: clean.dropped };
    events.push(event);
    if (events.length > capacity) events.splice(0, events.length - capacity);
    return { ok: true, event };
  }

  return {
    record,
    isEnabled: () => state.enabled,
    setEnabled(next) {
      const v = Boolean(next);
      state.enabled = v;
      if (!v) { events.length = 0; } // 关闭即清空：不留"先记着以后再看"的余地
      return v;
    },
    /**
     * 回填历史缓冲（popup 生命周期只有几十秒，缓冲必须落 storage 才取得到数）。
     * 只接受已过 schema 的形状，且**不重新清洗**——清洗在写入时已发生；
     * 容量仍受 capacity 约束，超出丢最旧。
     */
    restore(list) {
      if (!Array.isArray(list)) return 0;
      const keep = list.filter((e) => e && isKnownEvent(e.id) && e.props && typeof e.props === 'object');
      events.length = 0;
      events.push(...keep.slice(-capacity));
      return events.length;
    },
    list: () => events.slice(),
    stats: () => ({ buffered: events.length, dropped: droppedTotal, capacity }),
    clear() { events.length = 0; },
  };
}

/**
 * 本地聚合（§6.4「全部走本地聚合」）：按事件 id 汇总次数与数值分布，
 * 供设置页/导出面板直接渲染，不需要任何后端。
 */
export function summarize(events = []) {
  const out = {};
  for (const e of events) {
    const slot = out[e.id] ?? (out[e.id] = { count: 0, lastAt: 0, numeric: {}, bool: {} });
    slot.count += 1;
    slot.lastAt = Math.max(slot.lastAt ?? 0, e.at ?? 0);
    for (const [k, v] of Object.entries(e.props ?? {})) {
      if (typeof v === 'number') {
        const n = slot.numeric[k] ?? (slot.numeric[k] = { sum: 0, min: v, max: v, n: 0 });
        n.sum += v; n.n += 1; n.min = Math.min(n.min, v); n.max = Math.max(n.max, v);
      } else if (typeof v === 'boolean') {
        const b = slot.bool[k] ?? (slot.bool[k] = { true: 0, false: 0 });
        b[v ? 'true' : 'false'] += 1;
      }
    }
  }
  for (const slot of Object.values(out)) {
    for (const n of Object.values(slot.numeric)) {
      n.avg = n.n > 0 ? Math.round((n.sum / n.n) * 1000) / 1000 : 0;
    }
  }
  return out;
}

/**
 * §1.3 成功指标的可取数口径。这些指标里除了两条硬目标，其余基线值
 * PRD 明载 `[待补充]`——本函数只负责**从本地事件算出分子分母**，
 * 不替产品编造目标值。
 */
export function computeMetrics(events = []) {
  const count = (id, pred = () => true) => events.filter((e) => e.id === id && pred(e.props ?? {})).length;
  const opens = count('popup_open');
  const proofViews = count('screen_view', (p) => p.screenId === 'proofs' || p.tab === 'proofs');
  const portalStart = count('portal_verify_start');
  const portalOk = count('portal_verify_result', (p) => p.verdict === 'verified');
  const signApproved = count('sign_request_resolved', (p) => p.decision === 'approve');
  const signViaSession = count('sign_request_resolved', (p) => p.decision === 'approve' && p.via === 'session_key');
  return {
    /** 会话内访问「证明」tab 的占比（目标值 `[待补充]`，不编造）。 */
    proofsVisitRatio: opens > 0 ? proofViews / opens : null,
    /** 复验漏斗完成率（发起 → verified）。 */
    portalCompletion: portalStart > 0 ? portalOk / portalStart : null,
    /** 限额内免口令签名占比。 */
    sessionKeySignRatio: signApproved > 0 ? signViaSession / signApproved : null,
    /** 硬目标：必须恒为 0，>0 即说明禁用态表达失败（§1.3）。 */
    withdrawSubmitAttempts: count('withdraw_submit_attempt_blocked'),
    /** 硬目标：界面无价格源时 `—` 的渲染次数，用于回归监控。 */
    fiatUnavailableViews: count('fiat_unavailable_view'),
    /** R-18 词汇漂移监测：note proof 不在 PROOF_LADDER 内的次数。 */
    ladderMismatch: count('proof_ladder_mismatch'),
    /** 可复核性辅助：超过 500ms 交互预算的复验次数。 */
    overBudgetResults: count('portal_verify_result', (p) => p.overBudget === true),
  };
}

/** `portal_verify_step` 的便捷封装：把 ms 与超预算判定收在一处。 */
export function portalStepProps({ step, ok, ms, payloadBytes = null, engine = null, gatewayStatus = null }) {
  const props = { step, ok: ok === true, ms: Math.round(Number(ms) || 0) };
  if (payloadBytes != null) props.payloadKB = Math.round((Number(payloadBytes) / 1024) * 10) / 10;
  if (engine != null) props.engine = String(engine).slice(0, 16);
  if (gatewayStatus != null) props.gatewayStatus = String(gatewayStatus).slice(0, 16);
  return props;
}
