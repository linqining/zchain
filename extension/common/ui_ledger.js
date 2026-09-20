// =============================================================================
// extension/common/ui_ledger.js — 方向 B「账簿 / Ledger」UI 纯逻辑层
//
// 设计出处：design/zchain-wallet-ui-b-ledger.html（v0.2）。该方向对方向 A 的
// 结构性修正是：**三链共用同一套「账簿」骨架，链是筛选器而不是目的地**——
// 因此屏幕注册表里 acct / send / history / manage / contract 只有一份，按
// chain 换数据面；ZChain 层的「贪心选币 + 凭证阶梯」是账簿的 ZChain 专属面。
//
// 本模块只做**可被 node --test 覆盖的纯函数**：注册表与导航解析、金额与
// 地址格式化、凭证阶梯聚合、回执分桶、会话用量、时间文案、错误码文案。
// popup.js 只做 DOM 编排（CSP：无内联脚本，全部走 data-* + 事件委托）。
//
// 诚实边界（与钱包既有 fail-closed 纪律一致，测试逐条钉住）：
// - 无价格源：不做任何法币折算（`fiatOf` 恒 null），UI 必须显式标注未接入；
// - 跨域不轧差：REAL / GAME 金额永不合计（`sumAssets` 只按域内合计）；
// - 不推断：未知枚举值一律回落原始值，不造名称、不把 null 当 0。
// =============================================================================

/** 凭证阶梯（note 的 proof 状态，锚定在 note 上）。 */
export const PROOF_LADDER = ['pending', 'soft', 'proven', 'finalized'];

/** 投递状态机（回执：signed → seen → included）。与凭证阶梯是两套语义。 */
export const INCLUSION_LADDER = ['signed', 'seen', 'included'];

/** 价格源未接入（0.6 交付面无行情/预言机）——UI 据此显示「未接入」而非 0。 */
export const PRICE_SOURCE_CONNECTED = false;

// ---------------------------------------------------------------------------
// 屏幕注册表
// ---------------------------------------------------------------------------

/**
 * 屏幕清单（id 稳定，e2e 与导航都按 id 寻址）。
 * - `grp`：侧栏/审计分组；
 * - `tab`：底部三 tab 高亮归属（null = 无 tab 的子页）；
 * - `shared`：该屏按 chain 复用同一模板（链=筛选器）；
 * - `parent`：子页栏「返回」的目标（'@acct' = 回到账簿并沿用当前链）。
 */
export const SCREENS = [
  { id: 'welcome', grp: '引导', name: '欢迎 · 一次创建三层', tab: null, shared: false, parent: null },
  { id: 'success', grp: '引导', name: '创建成功 · 解锁口令', tab: null, shared: false, parent: 'home' },
  { id: 'import', grp: '引导', name: '导入 / 恢复', tab: null, shared: false, parent: 'welcome' },
  { id: 'lock', grp: '引导', name: '锁定 · 统一解锁', tab: null, shared: false, parent: 'home' },
  { id: 'home', grp: '账户', name: '三链总账', tab: 'home', shared: false, parent: null },
  { id: 'acct', grp: '账簿', name: '账簿 · 三链', tab: 'acct', shared: true, parent: null },
  { id: 'zc-send', grp: 'ZChain', name: '转账 · 贪心选币', tab: 'acct', shared: false, parent: '@acct' },
  { id: 'zc-withdraw', grp: 'ZChain', name: 'REAL 提现预览 · fail-closed', tab: 'acct', shared: false, parent: '@acct' },
  { id: 'zc-confirm', grp: 'ZChain', name: 'dapp 签名请求', tab: 'home', shared: false, parent: '@acct' },
  { id: 'zc-sessions', grp: 'ZChain', name: '会话密钥 · SNIP-12', tab: 'acct', shared: false, parent: '@acct' },
  { id: 'zc-portal', grp: 'ZChain', name: 'Proof Portal', tab: 'proofs', shared: false, parent: '@acct' },
  { id: 'zc-receipts', grp: 'ZChain', name: '回执状态机', tab: 'acct', shared: false, parent: '@acct' },
  { id: 'send', grp: '链层', name: '发送 · 交易预览', tab: 'acct', shared: true, parent: '@acct' },
  { id: 'contract', grp: '链层', name: '合约读写', tab: 'acct', shared: true, parent: '@acct' },
  { id: 'history', grp: '链层', name: '交易记录 · 双边对账', tab: 'acct', shared: true, parent: '@acct' },
  { id: 'manage', grp: '链层', name: '账户管理 · 危险区', tab: 'acct', shared: true, parent: '@acct' },
  { id: 'proofs', grp: '证明', name: '凭证簿', tab: 'proofs', shared: false, parent: null },
  { id: 'settings', grp: '系统', name: '设置 · 能力矩阵', tab: null, shared: false, parent: 'home' },
];

const SCREEN_INDEX = new Map(SCREENS.map((s) => [s.id, s]));

/** 链判别（账簿内三值封闭枚举；未知 → null，不猜）。 */
export const CHAINS = ['zc', 'evm', 'stk'];

export function chainOf(value) {
  return CHAINS.includes(value) ? value : null;
}

export function screenById(id) {
  return SCREEN_INDEX.get(id) ?? null;
}

/** 是否为需要链上下文的屏幕。 */
export function isSharedScreen(id) {
  const s = SCREEN_INDEX.get(id);
  return Boolean(s && s.shared && s.id !== 'acct');
}

/**
 * 解析一次导航：返回 {id, chain, error?}。
 * - `acct:evm` / `send:stk` 形式（冒号带链）与 `{id, chain}` 都接受；
 * - 共享屏幕缺链时沿用 lastChain；无 lastChain 回落 'zc'；
 * - 未知 id → {error:'UnknownScreen'}（不静默落首页）。
 */
export function resolveScreen(target, ctx = {}) {
  const lastChain = chainOf(ctx.lastChain) ?? 'zc';
  if (target && typeof target === 'object') {
    const s = resolveScreen(target.id, ctx);
    const c = chainOf(target.chain);
    if (s.error) return s;
    return { id: s.id, chain: SCREEN_INDEX.get(s.id).shared ? (c ?? lastChain) : null };
  }
  const raw = String(target ?? '').trim();
  const [idPart, chainPart] = raw.split(':');
  const s = SCREEN_INDEX.get(idPart);
  if (!s) return { error: 'UnknownScreen', target: raw };
  const chain = s.shared ? (chainOf(chainPart) ?? (s.id === 'acct' ? lastChain : lastChain)) : null;
  return { id: s.id, chain };
}

/** 子页栏返回目标（'@acct' 解析为账簿 + 当前链）。 */
export function backTarget(id, ctx = {}) {
  const s = SCREEN_INDEX.get(id);
  if (!s || !s.parent) return null;
  if (s.parent === '@acct') return { id: 'acct', chain: chainOf(ctx.chain) ?? 'zc' };
  return { id: s.parent, chain: null };
}

/** 底部 tab 归属（未知屏幕 → null）。 */
export function tabOf(id) {
  return SCREEN_INDEX.get(id)?.tab ?? null;
}

/** 三链标签（账簿链切换器与各处链名统一口径）。 */
export const CHAIN_LABEL = { zc: 'ZChain', evm: 'EVM', stk: 'Starknet' };

// ---------------------------------------------------------------------------
// 格式化（等宽数字：账簿的全部金额）
// ---------------------------------------------------------------------------

/**
 * 金额分组：千分位 + **保留原始小数位**（不补齐、不四舍五入、不造精度）。
 * 接受 string | number | bigint；非十进制数字一律原样回落（不静默变 0）。
 */
export function fmtAmount(value) {
  const raw = typeof value === 'string' ? value.trim() : String(value ?? '');
  const m = /^(-?)(\d+)(?:\.(\d+))?$/.exec(raw);
  if (!m) return raw;
  const int = m[2].replace(/^0+(?=\d)/, '');
  const grouped = int.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return `${m[1]}${grouped}${m[3] != null ? `.${m[3]}` : ''}`;
}

/**
 * 带符号金额（收支列）：正值加 +。
 */
export function fmtSigned(value, { positive = false, negative = false } = {}) {
  const s = fmtAmount(value);
  if (positive) return `+${s}`;
  if (negative) return s.startsWith('-') ? s : `-${s}`;
  return s;
}

/**
 * 展示精度表（R-27 / U-01 的裁决落地）。
 *
 * 裁决口径：**显示精度 ≠ 存储精度**。`fmtAmount` 保留原始终断结果、
 * 明确不补齐（账簿纪律：不造精度）；本表只负责"同一列数字纵向能对齐"
 * 这一件事，由展示层在 `fmtAmount` 之后**追加**小数零。
 *
 * 两条硬约束，缺一不可：
 * 1. **只补齐、不截断、不四舍五入**——上游 `formatUnits` 已经是截断
 *    （宁可少报不多报），展示层若再 round 就会把余额报高；
 * 2. 实际小数位**多于**目标位数时**全部保留**（不丢弃真实精度），
 *    所以 `0.25` → `0.2500`，而 `0.25009999` 原样透出。
 *
 * `erc20: null` = 按代币 `decimals` 由调用方传入，不在此表里写死。
 */
export const DISPLAY_DECIMALS = {
  play: 2,
  native: 2,
  note: 2,
  eth: 4,
  strk: 4,
  erc20: null,
  usd: 2,
  gwei: 2,
};

/**
 * 按展示精度补齐小数位（只在小数**位数**不足时追零）。
 * 非十进制值（`—`、空、协议原词）原样返回，不硬凑成 0.00。
 */
export function fmtDisplay(value, kind = 'note', { decimals = null } = {}) {
  const raw = typeof value === 'string' ? value.trim() : String(value ?? '');
  const target = decimals ?? DISPLAY_DECIMALS[kind];
  if (target == null) return fmtAmount(raw);
  const m = /^(-?)(\d+)(?:\.(\d+))?$/.exec(raw);
  if (!m) return fmtAmount(raw);
  const frac = m[3] ?? '';
  const padded = frac.length >= target ? frac : frac.padEnd(target, '0');
  return fmtAmount(`${m[1]}${m[2]}.${padded}`);
}

/** 法币等值：价格源未接入时**恒为 `—`**，不接受任何调用方传进来的数字（R-01）。 */
export function fmtFiat(_amount, { connected = PRICE_SOURCE_CONNECTED } = {}) {
  if (!connected) return '—';
  return null; // 价格源接入后由此处统一乘单一快照价（§13 C-02）
}

/**
 * 十进制字符串求和（BigInt 路径，禁止 `Number()`）。
 * u64 金额上限 18446744073709551615 超过 Number.MAX_SAFE_INTEGER，
 * 走浮点会静默丢精度——账簿的第一纪律是不静默。
 * @returns {{ok:true,total:string}|{ok:false,code:string,bad:string}}
 */
export function sumDecimals(values = []) {
  let total = 0n;
  for (const v of values) {
    const s = typeof v === 'string' ? v.trim() : String(v ?? '');
    if (!/^\d+$/.test(s)) return { ok: false, code: 'AmountInvalid', bad: s };
    total += BigInt(s);
  }
  return { ok: true, total: total.toString() };
}

/** u64 上限（`AmountOverflow` 的判定基准）。 */
export const U64_MAX = '18446744073709551615';

/**
 * note 凭证词汇归一（R-18）。
 *
 * 系统里存在两套同义不同名的枚举：note 侧 `ProofState::Pending` 与
 * verifier 侧 `FinalityLevel::Local`（`.name()` 返回 `"local"`）。
 * 旧口径把不认识的词**静默**回落 `pending`，等级信息无声丢失。
 * 现口径：显式别名表 + `known:false` 上报，调用方必须发
 * `proof_ladder_mismatch` 埋点，让漂移可见。
 */
export const PROOF_ALIASES = { local: 'pending' };

export function normalizeProof(raw) {
  if (PROOF_LADDER.includes(raw)) return { proof: raw, known: true, raw };
  const alias = typeof raw === 'string' ? PROOF_ALIASES[raw] : undefined;
  if (alias) return { proof: alias, known: true, raw, aliased: true };
  return { proof: 'pending', known: false, raw: raw == null ? null : String(raw) };
}


/** 地址/哈希缩略（首尾保留，中间省略号；短串原样）。 */
export function shortAddr(a, head = 10, tail = 6) {
  if (typeof a !== 'string' || a.length === 0) return '—';
  if (a.length <= head + tail + 1) return a;
  return `${a.slice(0, head)}…${a.slice(-tail)}`;
}

/** 相对时间（账簿「最新动态」行；无秒级时钟漂移补偿，只用于展示）。 */
export function relTime(ts, now = Date.now()) {
  if (!Number.isFinite(ts) || ts == null) return '—';
  const diff = Math.max(0, now - ts);
  const s = Math.floor(diff / 1000);
  if (s < 10) return '刚刚';
  if (s < 60) return `${s} 秒前`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m} 分钟前`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} 小时前`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d} 天前`;
  return new Date(ts).toISOString().slice(0, 10);
}

/** 剩余时间（过期倒计时；负值 = 已过期）。 */
export function remainText(msLeft) {
  if (!Number.isFinite(msLeft)) return '—';
  if (msLeft <= 0) return '已过期';
  const s = Math.ceil(msLeft / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const rs = s % 60;
  if (m < 60) return `${m}:${String(rs).padStart(2, '0')}`;
  const h = Math.floor(m / 60);
  return `${h}h ${m % 60}m`;
}

/** 有效期剩余（会话密钥：秒 → 「剩 6 天 12 小时」）。 */
export function validityRemain(unixSec, nowSec = Math.floor(Date.now() / 1000)) {
  if (!Number.isFinite(unixSec)) return '—';
  const left = unixSec - nowSec;
  if (left <= 0) return '已过期';
  const d = Math.floor(left / 86400);
  const h = Math.floor((left % 86400) / 3600);
  if (d > 0) return `剩 ${d} 天 ${h} 小时`;
  if (h > 0) return `剩 ${h} 小时`;
  return `剩 ${Math.ceil(left / 60)} 分钟`;
}

// ---------------------------------------------------------------------------
// 凭证阶梯 / 回执 / 会话（账簿一等内容）
// ---------------------------------------------------------------------------

export function proofRank(proof) {
  const i = PROOF_LADDER.indexOf(proof);
  return i < 0 ? 0 : i;
}

/**
 * note 集合 → 凭证阶梯聚合（计数 + 短板）。
 *
 * 未知/缺失 proof 仍回落 `'pending'`（fail-closed：不猜、不把 null 当 0），
 * 但**不再静默**——`mismatches` 列出原值，调用方须上报
 * `proof_ladder_mismatch`（R-18），否则词汇漂移会无声吞掉等级信息。
 * @param {Array<{amount?:string|number, proof?:string, spendable?:boolean}>} notes
 */
export function proofLadder(notes = []) {
  const counts = { pending: 0, soft: 0, proven: 0, finalized: 0 };
  const mismatches = [];
  let weak = null;
  let spendable = 0;
  for (const n of notes) {
    const norm = normalizeProof(n?.proof);
    // 别名命中（`local` → pending）**也要上报**：那正是 R-18 的词汇双轨信号——
    // verifier 侧 FinalityLevel::Local 与 note 侧 ProofState::Pending 同名不同源，
    // 静默映射会把等级差异藏起来。监测到 0 才可以说漂移已消除。
    if (!norm.known || norm.aliased) mismatches.push(norm.raw ?? 'null');
    const p = norm.proof;
    counts[p] += 1;
    if (n?.spendable !== false) spendable += 1;
    if (weak === null || proofRank(p) < proofRank(weak)) weak = p;
  }
  return {
    ladder: PROOF_LADDER.map((k) => ({ proof: k, count: counts[k] })),
    counts,
    weakest: notes.length ? weak : null,
    spendable,
    total: notes.length,
    mismatches,
  };
}

/**
 * 阶梯"本网络要求的等级"（R-05b）。
 *
 * ⚠ 这是**数据不是文案**：GAME 域设计基准 `proven`，devnet 放宽为 `soft`
 * （本地水龙头铸的 stub note 在 wallet-core 里只有 Soft，无批次根，
 * 不能谎称 proven）。换网时说明必须随之改变，界不得写死 `proven`。
 * 单一来源在 `transfer_preview.minProofForNetwork`，这里只做展示侧的
 * 文案装配，避免第二处硬编码。
 */
export function requiredProofText({ required, networkKind } = {}) {
  if (!required) return '本网络未定义凭证门槛';
  const net = networkKind ? `（${networkKind}）` : '';
  return `本网络要求 ${required}${net}`;
}

// ---------------------------------------------------------------------------
// 容量上限与超限说明（R-11：每处上限配常驻说明，不留"数据凭空消失"）
// ---------------------------------------------------------------------------

/** 与 `validation.LIMITS` / `receipts.MAX_RECEIPTS` / `sessions.MAX_SESSION_BINDINGS` 同值。 */
export const CAPACITY = {
  noteInputs: 16,
  noteOutputs: 16,
  receipts: 20,
  sessions: 16,
  chainTxs: 500,
  proofLog: 20,
};

/** 超限行为文案（fail-closed + 给出路，不只说"不行"）。 */
export function capacityNotice(kind, { count = null } = {}) {
  switch (kind) {
    case 'noteInputs':
      return `所需 note 数${count != null ? ` ${count}` : ''}超过单签上限 ${CAPACITY.noteInputs} 张，请先合并小额 note`;
    case 'receipts':
      return `本机仅保留最近 ${CAPACITY.receipts} 条回执，更早的不在此处`;
    case 'sessions':
      return `授权数已达上限 ${CAPACITY.sessions}，请先撤销不用的 origin`;
    case 'chainTxs':
      return `本机仅保留最近 ${CAPACITY.chainTxs} 条链上交易记录`;
    case 'proofLog':
      return `本机仅保留最近 ${CAPACITY.proofLog} 次复验记录`;
    default:
      return `已达上限 ${CAPACITY[kind] ?? '—'}`;
  }
}

/** 会话密钥"日累计"的重置口径（R-31：分窗按 UTC 日，不是本地零点）。 */
export const DAILY_RESET_TEXT = '日累计按 UTC 日重置（非本地零点）';

/** UTC 日序号——与 `sessions.js` 的 `Math.floor(nowSec / 86_400)` 同口径。 */
export function utcDayIndex(nowSec = Math.floor(Date.now() / 1000)) {
  return Math.floor(Number(nowSec) / 86_400);
}

/**
 * 标识符前缀标签（R-29）。
 *
 * tx hash / 回执 digest / hand_binding / request_id / note commitment 在五
 * 个屏里反复出现，而稿面它们**前缀互相撞车**（`0xc41d…` 既是买入 tx 又是
 * hand_binding），跨屏核对不可能。规则：**每个标识符前必须挂具名前缀**，
 * 前缀取自这张表，不得由页面各自发挥。
 */
export const ID_PREFIX = {
  tx: 'tx',
  digest: 'rc',
  handBinding: 'hb',
  requestId: 'req',
  noteCommitment: 'note',
  payoutRoot: 'root',
  sessionId: 'sess',
};

/** 具名缩略：`tx 0xc41d…9b04`，参数固定（同一字段类型全应用一组参数）。 */
export function idText(kind, value, { head = 10, tail = 6 } = {}) {
  const label = ID_PREFIX[kind] ?? kind ?? 'id';
  return `${label} ${shortAddr(value, head, tail)}`;
}


/**
 * 阶梯节点渲染态（design .rn 的四种笔触：done / cur / bad / 空）。
 *
 * `current` = 已到达的最弱层级；`outcome` 决定"下一格"怎么画：
 * - 'ok'      达标（例如提现要求已满足）→ 只画 done；
 * - 'blocked' 被卡住（fail-closed，提交入口禁用）→ 下一格画 bad（红）；
 * - 'wait'    仍在推进（等待证明/finality）→ 下一格画 cur（琥珀）；
 * - 'idle'    无数据 → 全空。
 *
 * 注意：凭证阶梯与回执投递状态（signed→seen→included）是两套语义，
 * 笔触刻意不同——不得用同一种芯片表达。
 */
export function ladderSteps({ current = null, outcome = 'idle', required = null } = {}) {
  const curIdx = current ? PROOF_LADDER.indexOf(current) : -1;
  if (curIdx < 0) {
    return PROOF_LADDER.map((k) => ({ proof: k, state: '', required: required === k }));
  }
  return PROOF_LADDER.map((k, i) => {
    let state = '';
    if (i <= curIdx) state = 'done';
    else if (i === curIdx + 1) {
      state = outcome === 'blocked' ? 'bad' : outcome === 'wait' ? 'cur' : '';
    }
    return { proof: k, state, required: required === k };
  });
}

/**
 * 回执分桶：all / pend（未上链：signed|seen）/ done（included）。
 * `pastDeadline` 单独透出——超期是 ForceInclude 协议提示，不改分桶。
 */
export function receiptBuckets(receipts = []) {
  const list = Array.isArray(receipts) ? receipts : [];
  const pend = list.filter((r) => r?.status !== 'included');
  const done = list.filter((r) => r?.status === 'included');
  const stale = list.filter((r) => r?.view?.pastDeadline === true);
  return { all: list, pend, done, stale };
}

/** 回执状态芯片（措辞与「未验签/未实现提交」红线一致）。 */
export function receiptChip(receipt) {
  const status = receipt?.status ?? 'signed';
  const past = receipt?.view?.pastDeadline === true;
  if (status === 'included') return { text: 'included', cls: 'ch-felt' };
  if (status === 'seen') return { text: past ? 'seen 超期' : 'seen', cls: past ? 'ch-bad' : 'ch-play' };
  return { text: past ? 'signed 超期' : 'signed', cls: past ? 'ch-bad' : 'ch-amb' };
}

/** 链上交易状态芯片（EVM / Starknet 共用；status 词汇两侧不同，映射集中在这里）。 */
export function txStatusChip(status) {
  if (status === 'confirmed' || status === 'succeeded') return { text: '成功', cls: 'ch-felt' };
  if (status === 'failed' || status === 'reverted') return { text: status === 'failed' ? '失败' : '已回退', cls: 'ch-bad' };
  return { text: '待确认', cls: 'ch-amb' };
}

/** 交易记录分桶：all / tx（转账）/ c（合约）。 */
export function historyBuckets(txs = []) {
  const list = Array.isArray(txs) ? txs : [];
  return {
    all: list,
    tx: list.filter((t) => t?.kind !== 'contract'),
    c: list.filter((t) => t?.kind === 'contract'),
  };
}

/** 转账方向（相对本账户地址）：in / out / self。 */
export function txDirection(tx, selfAddress) {
  const self = String(selfAddress ?? '').toLowerCase();
  const from = String(tx?.from ?? '').toLowerCase();
  const to = String(tx?.to ?? '').toLowerCase();
  if (!self) return 'out';
  if (from === self) return 'out';
  if (to === self) return 'in';
  return 'out';
}

/** 会话密钥日限额用量（无日限 → percent null，UI 不画进度条）。 */
export function sessionUsage(binding) {
  const limit = binding?.perDayLimit;
  const used = binding?.dailyUsedToday ?? '0';
  if (limit == null || limit === '') {
    return { percent: null, usedText: String(used), limitText: '不限' };
  }
  const u = BigInt(used || '0');
  const l = BigInt(limit || '1');
  const percent = l > 0n ? Math.min(100, Number((u * 100n) / l)) : 100;
  return { percent, usedText: String(used), limitText: String(limit), exhausted: u >= l };
}

export const SESSION_STATUS_CHIP = {
  active: { text: '活跃', cls: 'ch-felt' },
  exhausted: { text: '已耗尽', cls: 'ch-amb' },
  revoked: { text: '已撤销', cls: 'ch-bad' },
  expired: { text: '已过期', cls: 'ch-amb' },
  not_yet_valid: { text: '未生效', cls: '' },
  unknown: { text: '未知', cls: '' },
};

export function sessionStatusChip(status) {
  return SESSION_STATUS_CHIP[status] ?? { text: String(status ?? '未知'), cls: '' };
}

// ---------------------------------------------------------------------------
// 错误码 → 文案（全 UI 单一口径；未知码原样透出 code，不吞）
// ---------------------------------------------------------------------------

export const ERROR_TEXT = {
  BadPassword: '口令错误（fail-closed）',
  SessionInvalid: '钱包已锁定，请先解锁',
  NoKeystore: '还没有钱包：请先创建或导入',
  NoAccount: '还没有该层账户：请先创建或导入',
  OnboardedAlready: '已存在钱包：请用口令解锁，不会被一键创建覆盖',
  // R-26：不写"mainnet 刻意不开放"——该策略**只适用于 ZChain 层**，EVM 层
  // 注册表含 Ethereum 0x1，Starknet 亦有主网条目。笼统措辞会让用户以为
  // 整个钱包不能上主网（而同一屏就在展示 chainId 1）。
  NetworkUnsupported: '该网络不在注册表内（未注册即不可用；ZChain 层刻意不含 mainnet）',
  InvalidArgument: '输入不合法',
  AmountInvalid: '金额不合法',
  AmountOverflow: '金额超出可表示范围',
  OwnerInvalid: '收款地址格式不合法',
  InsufficientFunds: '可用余额不足（note 全额消费，不支持部分花费）',
  NoChangeAllowed: '选币结果无法平衡：需要找零输出但收款方已满',
  NoSpendableNote: '没有可花费的 note',
  PreviewMismatch: '预览摘要与签名内容不一致（已拒绝）',
  NoDraft: '没有待确认交易，请重新发起',
  NoteNotFound: '输入 note 不在本账户库中（可能已被消费）',
  NoteNotSpendable: '输入 note 已锁定，不可花费',
  ProofBelowGate: '凭证层级低于该网络的支出门槛',
  DraftExpired: '交易预览已过期，请重新发起',
  UserRejected: '已取消',
  RequestExpired: '请求已超时',
  RpcUnreachable: 'RPC 不可达（未伪造结果）',
  GatewayNotConfigured: '当前网络未配置网关',
  GatewayUnreachable: '网关不可达（未伪造结果）',
  GatewayTimeout: '网关超时',
  SettlementNotFound: '该 hand binding 无结算明细',
  ProofNotFound: '无已归档证明产物',
  StarkVerifyRejected: 'STARK 证明验证未通过',
  WalletCoreError: '钱包内核错误',
  Tampered: '备份已篡改或结构非法（fail-closed）',
  UnsupportedVersion: '备份版本不受支持（只升不降）',
  BackupRejected: '备份被拒绝',
  OriginNotPermitted: '该站点未获授权',
  DuplicateReceipt: '回执已存在',
  ProofTooLarge: '证明体积超出可验证上限（已拒绝下载）',
  TelemetryDisabled: '本地诊断记录未开启',
  InternalError: '内部错误',
};

export function errorText(err, { maxLen = 200 } = {}) {
  if (!err) return '';
  const code = typeof err === 'string' ? err : String(err.code ?? 'Error');
  const reason = typeof err === 'string' ? '' : String(err.reason ?? err.detail ?? '');
  const base = ERROR_TEXT[code] ?? code;
  const text = reason ? `${base}：${reason}` : base;
  return text.length > maxLen ? `${text.slice(0, maxLen)}…` : text;
}

// ---------------------------------------------------------------------------
// 合计边界（跨域禁轧差）
// ---------------------------------------------------------------------------

/**
 * 域内合计（同域同 token 才可相加）。跨域调用直接 fail-closed。
 * @returns {{ok:true,total:string}|{ok:false,code:string}}
 */
export function sumWithinDomain(values, domain) {
  if (typeof domain !== 'string' || domain.length === 0) {
    return { ok: false, code: 'DomainRequired' };
  }
  let total = 0n;
  for (const v of values) {
    const s = typeof v === 'string' ? v.trim() : String(v ?? '');
    if (!/^\d+$/.test(s)) return { ok: false, code: 'AmountInvalid', value: s };
    total += BigInt(s);
  }
  return { ok: true, total: total.toString(), domain };
}

/** 底色切换（纸白 / 夜场）——纯函数，持久化在 popup 侧。 */
export function nextGround(current) {
  return current === 'night' ? 'paper' : 'night';
}

/** 屏幕标题（票据抬头第二行的语义锚点）。 */
export function screenTitle(id, chain) {
  const s = SCREEN_INDEX.get(id);
  if (!s) return 'ZChain Wallet';
  if (s.id === 'acct') return `账簿 · ${CHAIN_LABEL[chainOf(chain) ?? 'zc']} 层`;
  return s.name;
}

// ---------------------------------------------------------------------------
// outcome 判定与边界态文案（此前散在四个渲染点各自 inline 推导）
// ---------------------------------------------------------------------------

/**
 * 凭证阶梯的 `outcome` 唯一出口（AC-09 / AC-10）。
 *
 * 同一 `weakest=soft` 在首页要画琥珀 cur、在提现页要画朱红 bad——差别不在
 * 数据而在**这一格是不是被 fail-closed 卡住**。此前 popup 四处各自
 * `weakest !== 'finalized' ? 'wait' : 'ok'`，提现页靠传参碰对；一旦某处
 * 忘记传 `canSubmit`，禁用态就会被画成"仍在推进"的琥珀色——那正是
 * "把不可用说成等一下就好"的界面事故（R-07 同族）。
 *
 * @returns {'idle'|'ok'|'blocked'|'wait'}
 */
export function ladderOutcome({ weakest = null, required = null, canSubmit = null, spendable = null } = {}) {
  if (weakest == null) return 'idle';
  if (canSubmit === false) return 'blocked';
  if (spendable === 0) return 'blocked';
  if (required != null && proofRank(weakest) < proofRank(required)) return 'wait';
  return 'ok';
}

/**
 * 限额 / 超限的统一原因文案（R-06 的五个未演示态、R-11 的三处上限）。
 * 规则：禁用必须**给原因 + 给出路**，不能只置灰。
 */
export function limitReasonText(code, params = {}) {
  switch (code) {
    case 'noteCountOverLimit':
      return `所需 note 数 ${params.count ?? '—'} 超过单签上限 ${CAPACITY.noteInputs}，请先合并小额 note`;
    case 'previewExpired':
      return '交易预览已过期（超过 5 分钟），请重新发起——note 集合可能已被桌台消费';
    case 'sessionLimitReached':
      return `授权数已达上限 ${CAPACITY.sessions}，请先撤销不用的 origin`;
    case 'perTxOverLimit':
      return `本笔 ${params.amount ?? '—'} 超过单笔限额 ≤${params.perTxLimit ?? '—'}，需输入口令确认`;
    case 'dailyExhausted':
      return `本会话日累计已耗尽（${params.used ?? '—'}/${params.limit ?? '—'}，${DAILY_RESET_TEXT}），需输入口令`;
    case 'noDayLimit':
      return '未设日累计上限';
    case 'receiptCapacity':
      return capacityNotice('receipts');
    case 'scopesEmpty':
      return '请至少选择一项授权范围';
    default:
      return null;
  }
}

/** 十进制串减法，下钳 0（u64 安全；"可用 = 余额 − 在途" 的唯一出口）。 */
export function subClampedDecimal(a, b) {
  const x = String(a ?? '0').trim();
  const y = String(b ?? '0').trim();
  if (!/^\d+$/.test(x) || !/^\d+$/.test(y)) return null;
  const left = BigInt(x) - BigInt(y);
  return left > 0n ? left.toString() : '0';
}

// ---------------------------------------------------------------------------
// 合计与凭证簿计数（AC-02 / AC-04 / R-36）
// ---------------------------------------------------------------------------

/**
 * 按域合计（AC-04：合计必须由求和函数产出，禁止硬编码字面量）。
 *
 * 输入是 `assets.groupBalances()` 一类的分组结果 `{ [domain]: [{amount}] }`；
 * **跨域永不轧差**——REAL 是托管债权、GAME 是无价值筹码，相加即撒谎（D-06）。
 * 因此返回值是"逐域各一个合计"，界面无从把一个总数写死。
 *
 * @returns {Record<string, {ok:boolean,total:string|null,code?:string}>}
 */
export function domainTotals(grouped = {}) {
  const out = {};
  for (const [domain, rows] of Object.entries(grouped)) {
    const list = Array.isArray(rows) ? rows : [];
    const sums = sumDecimals(list.map((r) => (typeof r === 'string' ? r : r?.amount)));
    out[domain] = sums.ok
      ? { ok: true, total: sums.total, count: list.length }
      : { ok: false, total: null, code: sums.code, bad: sums.bad };
  }
  return out;
}

/**
 * 本机复验记录的计数口径（R-36）。
 *
 * 稿面写「最近 24 小时 · 5 份结算证明」，代码里的 proof log **没有时间字段、
 * 也没有时间过滤**，上限 20 条。二者不能都成立。此处按可实现口径给出：
 * 「最近 N 次本地复验」，并区分"次数"与"份数"（同一手牌复验两次是 2 次
 * 不是 2 份）。若记录带 `atMs` 则可另给 24h 过滤值，不带就返回 null——
 * 不为了文案好看而假装过滤过。
 */
export function proofLogSummary(log = []) {
  const list = Array.isArray(log) ? log : [];
  const allOk = list.filter((e) => e?.verdict === 'verified').length;
  const dated = list.filter((e) => Number.isFinite(e?.atMs));
  const newest = dated.reduce((m, e) => Math.max(m, e.atMs), 0);
  // 一条带时间戳的记录都没有时，24h 窗口必须是 **null**（不是 0）——
  // "24 小时内 0 次" 是一个看起来像数据的假结论，正是 DS-13 禁止的那类补齐。
  const within24h = dated.length > 0
    ? dated.filter((e) => newest - e.atMs <= 24 * 3600 * 1000).length
    : null;
  const bindings = new Set(list.map((e) => e?.binding).filter(Boolean));
  return {
    count: list.length,
    verifiedCount: allOk,
    distinctBindings: bindings.size,
    within24h,
    // 计数文案：无时间戳时只报"次"，不报"小时窗口"（不编造窗口）。
    text: within24h != null
      ? `最近 ${list.length} 次本地复验（24 小时内 ${within24h} 次）`
      : `最近 ${list.length} 次本地复验`,
    capacityText: list.length >= CAPACITY.proofLog ? capacityNotice('proofLog') : null,
  };
}

