// =============================================================================
// extension/popup/popup.js — ZChain Wallet 弹窗（方向 B「账簿 / Ledger」v0.2）
//
// 设计出处：design/zchain-wallet-ui-b-ledger.html。本文件是**屏幕注册表的执行
// 者**：只做 DOM 编排与消息派发；屏幕结构/导航关系/金额口径/阶梯语义/错误文案
// 全部来自 common/ui_ledger.js（纯函数，node --test 覆盖）。
//
// 结构上对方向 A 的三处修正（设计稿立场）：
//   1. 链 = 筛选器，不是目的地：acct/send/contract/history/manage 一套模板按
//      chain 换数据面，不再为 EVM 与 Starknet 各写一遍仪表盘；
//   2. 凭证（proof/finality）是一等公民组件（.rail 凭证条），不是二级页面：
//      首页/账簿/提现预览/凭证簿共用同一 ladder 语义；
//   3. 投递状态（signed→seen→included）与凭证阶梯（pending→proven→finalized）
//      是两套状态机，芯片笔触刻意不同，不得混用。
//
// 交互实现：CSP `script-src 'self'` → 无内联脚本、无内联事件处理器；一切交互
// 走 data-* 属性 + 单一事件委托（data-nav / data-act / data-open / data-close /
// data-copy / data-toast / data-seg / data-cs / data-check）。
//
// 诚实边界（与后台红线一致，UI 不越权）：
//   - 无价格源 → 不显示任何法币折算（合计处显式标注「未接入」）；
//   - REAL/GAME 物理分库 → 跨域金额永不合计；
//   - REAL 提现 canSubmit 恒 false（wallet-core 展示门 + finality 合取，UI 只消费）；
//   - 网关水位/回执证据原样展示，未验签就写未验签；ForceInclude 只有状态、无提交；
//   - mainnet 不在注册表内 → 网络选择器里没有它就是没有它，不加"隐藏选项"；
//   - 二维码编码器未接入 → 收款页不画假码，只给完整地址 + 复制。
//
// 日志纪律（WALLET-ACC-4）：本文件不使用 console 输出任何请求内容；口令只存在
// 于表单值并直接传给后台，不落 storage、不入日志。
// =============================================================================

import { groupBalances, assetBadge } from '../common/assets.js';
import {
  parseBinding, fetchSettlement, fetchProof, verifyStarkProof, verifyLocally, verdictRows,
} from '../common/portal.js';
import { callCore } from '../common/wallet_core.js';
import { verifyCanonicalArchive } from '../common/stwo_verify.js';
import {
  CHAIN_LABEL, ERROR_TEXT, PRICE_SOURCE_CONNECTED,
  backTarget, chainOf, errorText, fmtAmount, fmtSigned, historyBuckets,
  ladderSteps, nextGround, proofLadder, receiptBuckets, receiptChip,
  relTime, remainText, resolveScreen, sessionStatusChip, sessionUsage,
  shortAddr, tabOf, txDirection, txStatusChip, validityRemain,
} from '../common/ui_ledger.js';

const $view = document.getElementById('view');
const $toast = document.getElementById('toast');

const send = (m) => chrome.runtime.sendMessage(m);

// ---------------------------------------------------------------------------
// 运行时状态（只活在一次弹窗生命周期；口令一律不进入本对象）
// ---------------------------------------------------------------------------

const rt = {
  screen: 'home',
  chain: 'zc',            // 账簿当前链（链=筛选器）
  ground: 'paper',        // 纸白 / 夜场
  hideAmount: false,      // 总额显隐（公共场所）
  overview: null,         // popup:overview 快照（每次 render 刷新）
  evmInfo: null,          // 最近一次 evmRefresh（跨渲染保留，避免"刷新完就没了"）
  stkInfo: null,          // 最近一次 stkRefresh
  created: null,          // 一键创建结果（成功页显示一次口令，之后即丢）
  draft: null,            // 会话密钥草稿（SNIP-12 摘要确认中）
  transfer: null,         // PLAY 转账预览（wallet-core 摘要绑定后才可提交）
  withdraw: null,         // REAL 提现预览（展示态；canSubmit 恒 false）
  gate: null,             // 链层读/写草稿（kind: read | write | send；跨屏不复用）
  history: null,          // 交易记录结果
  portal: null,           // Portal 验证进度与结论
  form: {},               // 表单草稿（重渲染不丢已填内容；提交成功后清除）
  ovl: null,              // 当前打开的浮层 id（render 重建 DOM 后重新挂上）
  seq: 0,
};

const GROUND_KEY = 'zchain.ui.ground';
const HIDE_KEY = 'zchain.ui.hideAmount';

function loadPrefs() {
  try {
    rt.ground = localStorage.getItem(GROUND_KEY) === 'night' ? 'night' : 'paper';
    rt.hideAmount = localStorage.getItem(HIDE_KEY) === '1';
  } catch { /* 存储不可用：保持默认，不影响功能 */ }
  applyGround();
}

function applyGround() {
  document.documentElement.dataset.ground = rt.ground;
}

function persistPrefs() {
  try {
    localStorage.setItem(GROUND_KEY, rt.ground);
    localStorage.setItem(HIDE_KEY, rt.hideAmount ? '1' : '0');
  } catch { /* 同上 */ }
}

// ---------------------------------------------------------------------------
// DOM 构造助手（全部 createElement：无 innerHTML 注入面）
// ---------------------------------------------------------------------------

function h(tag, attrs = {}, kids = []) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = String(v);
    else if (v === true) n.setAttribute(k, '');
    else n.setAttribute(k, String(v));
  }
  for (const kid of (Array.isArray(kids) ? kids : [kids])) {
    if (kid === null || kid === undefined || kid === false) continue;
    n.appendChild(typeof kid === 'string' || typeof kid === 'number' ? document.createTextNode(String(kid)) : kid);
  }
  return n;
}

/** 单线图标（sprite <use>；方头 1.6 stroke）。 */
function ic(name, cls = 'ic') {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', cls);
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', `#i-${name}`);
  svg.appendChild(use);
  return svg;
}

function logo(cls, style) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', cls);
  svg.setAttribute('viewBox', '0 0 64 64');
  svg.setAttribute('aria-label', 'ZChain 单色 logo');
  if (style) svg.setAttribute('style', style);
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', '#z-logo');
  svg.appendChild(use);
  return svg;
}

function chip(text, cls = '') {
  return h('span', { class: `ch ${cls}`.trim() }, [text]);
}

function seal(text, cls = 'seal-ok') {
  return h('span', { class: `seal ${cls}` }, [text]);
}

function iconBtn(name, { bare = false, attrs = {}, title = '' } = {}) {
  return h('button', { class: `ib ${bare ? 'bare' : ''}`.trim(), type: 'button', title, ...attrs }, [ic(name)]);
}

/** 账簿行：label / value 细线对（value 等宽右对齐，永不折行）。 */
function lr(k, v, { dim = false, vKids = null, hash = false, kStyle = '' } = {}) {
  const key = typeof k === 'string'
    ? h('span', { class: `lr-k ${hash ? 'hashline' : ''}`.trim(), style: kStyle || undefined, text: k })
    : h('span', { class: 'lr-k' }, [k]);
  return h('div', { class: 'lr' }, [
    key,
    vKids
      ? h('span', { class: `lr-v ${dim ? 'dim' : ''}`.trim() }, vKids)
      : h('span', { class: `lr-v ${dim ? 'dim' : ''}`.trim(), text: String(v ?? '') }),
  ]);
}

/** 卡片（纸卡 + 细线 + 等宽小标题 + 右侧「更多」入口）。 */
function cd(title, kids = [], { more, moreAttrs = {}, cls = '', id = null } = {}) {
  const c = h('div', { class: `cd ${cls}`.trim(), id: id || undefined });
  if (title !== null) {
    const head = h('div', { class: 'cd-h' }, [title]);
    if (more) head.appendChild(h('button', { class: 'more', type: 'button', ...moreAttrs }, [more, ic('chev-r', 'ic ic-xs')]));
    c.appendChild(head);
  }
  for (const k of kids) if (k) c.appendChild(k);
  return c;
}

function secT(text, { danger = false } = {}) {
  return h('div', { class: `sec-t ${danger ? 'danger' : ''}`.trim() }, [text]);
}

function btn(label, { cls = 'btn-p', id, disabled, attrs = {}, icon = null } = {}) {
  return h('button', {
    class: `btn ${cls}`, type: 'button', id,
    disabled: disabled ? '' : null, ...attrs,
  }, [icon ? ic(icon, 'ic ic-s') : null, label]);
}

function banner(kind, title, body) {
  const iconName = kind === 'bad' ? 'warn' : kind === 'real' ? 'warn' : kind === 'ok' ? 'shield' : kind === 'amb' ? 'lock' : 'info';
  return h('div', { class: `bn bn-${kind}` }, [
    ic(iconName),
    h('div', {}, [h('b', { text: title }), body ? h('p', { text: body }) : null]),
  ]);
}

function emptyBox(text) {
  return h('div', { class: 'empty', text });
}

function input(id, { placeholder = '', type = 'text', value = '', cls = '', attrs = {} } = {}) {
  return h('input', { id, type, placeholder, class: cls, value, autocomplete: 'off', spellcheck: 'false', ...attrs });
}

/**
 * 表单草稿：render() 会重建整棵屏幕树，已填内容若不入草稿就每次动作后丢失
 * （读合约 → 地址被清空 → 再写就报"地址非法"）。只存表单值，不存口令。
 */
function formVal(id) {
  return rt.form[id] ?? '';
}
function captureForm(...ids) {
  for (const id of ids) {
    const n = document.getElementById(id);
    if (n && n.type !== 'password') rt.form[id] = n.value;
  }
}
function dropForm(...ids) {
  for (const id of ids) delete rt.form[id];
}

function field(label, inputNode, { aux = '', auxBtn = null, id = null } = {}) {
  const fl = h('div', { class: 'fl' }, [label]);
  if (aux || auxBtn) {
    const a = h('span', { class: 'aux' }, [aux]);
    if (auxBtn) a.appendChild(h('button', { type: 'button', ...auxBtn.attrs }, [auxBtn.text]));
    fl.appendChild(a);
  }
  return h('div', { class: 'fld', id }, [fl, inputNode]);
}

/** 金额输入（账簿封面的大字等宽输入 + 右侧单位块）。 */
function amountInput(id, { value = '', unit, tkCls = '', placeholder = '0', attrs = {} } = {}) {
  return h('div', { class: 'iw' }, [
    input(id, { cls: 'inp-amt', value, placeholder, attrs: { inputmode: 'decimal', ...attrs } }),
    h('span', { class: 'tsel' }, [h('span', { class: `tk ${tkCls}`.trim(), style: 'width:18px;height:18px;font-size:9px' }, [unit.slice(0, 1)]), unit]),
  ]);
}

/** 错误行 / 成功行（就地显示，不弹层）。 */
function errLine(id = 'err') {
  return h('div', { class: 'errx', id, role: 'alert' });
}
function okLine(id = 'ok') {
  return h('div', { class: 'okx', id });
}

function nodeErr(scope) {
  if (!scope) return null;
  return scope.querySelector?.('.errx') ?? null;
}
function setErr(scope, err, extra = '') {
  const n = nodeErr(scope);
  if (!n) return;
  n.replaceChildren();
  if (!err) {
    n.textContent = extra;
    return;
  }
  const code = typeof err === 'string' ? err : err.code;
  n.appendChild(document.createTextNode(errorText(err)));
  // 稳定错误码原样附在文案后（中文口径给人读，code 给排查/测试对照；不吞码）。
  if (code && ERROR_TEXT[code]) n.appendChild(h('code', { class: 'code', text: code }));
}
function clearErr(scope) {
  const n = nodeErr(scope);
  if (n) n.textContent = '';
}

/** 资产行（token 方块 / 名称 + 芯片 / 副行 / 右金额）。 */
function assetRow({ tk = '', tkCls = '', name, nameKids, sub, amount, amountCls = '', rightKids, attrs = {} }) {
  return h('div', { class: 'ar', ...attrs }, [
    h('span', { class: `tk ${tkCls}`.trim() }, [tk]),
    h('div', { class: 'ar-m' }, [
      h('div', { class: 'ar-n' }, [name, ...(nameKids ?? [])]),
      sub ? h('div', { class: 'ar-s', text: sub }) : null,
    ]),
    h('div', { class: 'ar-r' }, [
      amount !== null && amount !== undefined ? h('div', { class: `ar-amt ${amountCls}`.trim(), text: amount }) : null,
      rightKids,
    ]),
  ]);
}

/** 交易/动态行。 */
function txRow({ iconName, ticCls = '', name, sub, amount, amountCls = '', chipNode, rightKids, attrs = {} }) {
  return h('div', { class: 'tx', ...attrs }, [
    h('span', { class: `tic ${ticCls}`.trim() }, [ic(iconName, 'ic ic-s')]),
    h('div', { class: 'ar-m' }, [
      h('div', { class: 'ar-n', text: name }),
      sub ? h('div', { class: 'ar-s', text: sub }) : null,
    ]),
    h('div', { class: 'ar-r' }, [
      amount ? h('div', { class: `ar-amt ${amountCls}`.trim(), text: amount }) : null,
      h('div', { class: 'ar-st' }, [chipNode, rightKids]),
    ]),
  ]);
}

/** 菜单行（图标方块 / 标题 + 副行 / 右侧芯片或箭头）。 */
function mi({ iconName, title, sub, right, danger = false, attrs = {}, icStyle = '' }) {
  return h('button', { class: `mi ${danger ? 'danger' : ''}`.trim(), type: 'button', ...attrs }, [
    h('span', { class: 'mi-ic', style: icStyle || undefined }, [ic(iconName, 'ic ic-s')]),
    h('span', { class: 'grow' }, [h('b', { text: title }), h('span', { text: sub ?? '' })]),
    right ?? ic('chev-r', 'ic ic-s'),
  ]);
}

/** 凭证条（finality 阶梯：done/cur/bad/空 四态笔触）。 */
function rail(steps, { capLeft, capRight } = {}) {
  const r = h('div', { class: 'rail' });
  steps.forEach((s, i) => {
    r.appendChild(h('div', { class: `rn ${s.state}`.trim() }, [h('i'), h('span', { text: s.proof })]));
    if (i < steps.length - 1) r.appendChild(h('div', { class: `rline ${s.state === 'done' ? 'done' : ''}`.trim() }));
  });
  if (!capLeft && !capRight) return r;
  return h('div', {}, [r, h('div', { class: 'rail-cap' }, [
    typeof capLeft === 'string' ? h('span', { text: capLeft }) : capLeft,
    capRight,
  ])]);
}

function meter(percent, { warn = false, style = '' } = {}) {
  const w = percent === null || percent === undefined ? 0 : Math.max(0, Math.min(100, percent));
  return h('div', { class: 'meter', style: style || undefined }, [h('i', { class: warn ? 'warn' : '', style: `width:${w}%` })]);
}

/** 方形勾选（配合 data-check 门控：全不勾时被门控的按钮自动禁用）。 */
function chk(text, { on = false, gate = null, style = '', id = null } = {}) {
  return h('label', { class: 'chk', id: id || undefined, style: style || undefined, ...(gate ? { 'data-check': `[data-gated=${gate}]` } : {}) }, [
    h('span', { class: `cb ${on ? 'on' : ''}`.trim() }, [ic('check', 'ic ic-xs')]),
    text,
  ]);
}

/** 完整地址 + 复制（二维码编码器未接入 → 不画假码）。 */
function passBox(id, text, { copyTitle = '复制' } = {}) {
  return h('div', { class: 'pass' }, [
    h('span', { class: 'grow', id, text: String(text ?? '—') }),
    iconBtn('copy', { attrs: { 'data-copy': `#${id}`, id: `${id}-copy`, title: copyTitle } }),
  ]);
}

// ---------------------------------------------------------------------------
// toast / 浮层 / 导航
// ---------------------------------------------------------------------------

let toastTimer = null;
function toast(msg, ms = 2600) {
  if (!$toast) return;
  $toast.textContent = String(msg);
  $toast.classList.add('on');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => $toast.classList.remove('on'), ms);
}

function currentScr() {
  return $view.querySelector('.scr.on') ?? $view;
}

function openOvl(name) {
  rt.ovl = name;
  applyOvl();
}

/** 把浮层开合状态重新贴到当前屏幕树上（render 会重建 DOM，状态不能只活在节点上）。 */
function applyOvl() {
  if (!rt.ovl) return;
  const scr = currentScr();
  const o = scr?.querySelector(`#${CSS.escape(rt.ovl)}`) ?? document.getElementById(rt.ovl);
  if (o) o.classList.add('on');
  else rt.ovl = null; // 目标节点不在本屏：状态随之作废
}

function closeOvl(target) {
  const o = target.closest('.ovl, .mdl-bg');
  if (!o) return;
  o.classList.remove('on');
  if (o.id === rt.ovl) rt.ovl = null;
}

function closeAllSheets() {
  for (const o of $view.querySelectorAll('.ovl.on, .mdl-bg.on')) o.classList.remove('on');
  rt.ovl = null;
}

/** 注入式底部抽屉（挂进当前 .scr，保证定位在 380×600 视口内）。 */
let sheetSeq = 0;
function openSheetNode(title, kids) {
  const id = `ovl-dyn-${++sheetSeq}`;
  const ovl = h('div', { class: 'ovl on', id }, [
    h('div', { class: 'ovl-bg', 'data-close': '1' }),
    h('div', { class: 'sheet' }, [
      h('div', { class: 'grab' }),
      h('div', { class: 'row', style: 'margin-bottom:8px' }, [
        h('div', { style: 'font-weight:600;font-size:13px;flex:1', text: title }),
        iconBtn('x', { bare: true, attrs: { 'data-close': '1' } }),
      ]),
      errLine(`sheet-err-${id}`),
      ...kids,
    ]),
  ]);
  currentScr().appendChild(ovl);
  return id;
}

/** 注入式模态（危险区二次确认）。 */
function openModalNode(title, kids) {
  const id = `mdl-dyn-${++sheetSeq}`;
  const m = h('div', { class: 'mdl-bg on', id }, [
    h('div', { class: 'mdl' }, [h('h3', { text: title }), ...kids]),
  ]);
  currentScr().appendChild(m);
  return id;
}

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(String(text ?? ''));
    return true;
  } catch {
    return false;
  }
}

/** data-copy 值：`#elementId` 取该节点文本，否则按字面量。 */
async function doCopy(spec) {
  let text = spec;
  if (typeof spec === 'string' && spec.startsWith('#')) {
    text = (document.getElementById(spec.slice(1))?.textContent ?? '').trim();
  }
  const okc = await copyText(text);
  toast(okc ? '已复制到剪贴板' : '复制失败：请手动选择文本');
}

/** 导航（屏幕注册表是唯一权威；未知屏幕如实提示，不静默回落）。 */
function go(target) {
  const r = resolveScreen(target, { lastChain: rt.chain });
  if (r.error) {
    toast(`未知屏幕：${r.target ?? ''}`);
    return;
  }
  if (r.chain) rt.chain = r.chain;
  rt.screen = r.id;
  render();
}

function back() {
  const t = backTarget(rt.screen, { chain: rt.chain });
  if (!t) return render();
  go(t);
}

// ---------------------------------------------------------------------------
// 事件委托（唯一监听点）
// ---------------------------------------------------------------------------

const ACTS = {};

/** 注册屏幕动作处理器（渲染器用 data-act 声明，逻辑集中在 act()）。 */
function act(name, fn) { ACTS[name] = fn; }

$view.addEventListener('click', async (e) => {
  const t = e.target;

  const closer = t.closest('[data-close]');
  if (closer) { closeOvl(closer); return; }

  const nav = t.closest('[data-nav]');
  if (nav) { go(nav.getAttribute('data-nav')); return; }

  if (t.closest('[data-back]')) { back(); return; }

  const seg = t.closest('[data-seg]');
  if (seg) {
    const host = seg.closest('.scr') ?? $view;
    const key = seg.getAttribute('data-seg');
    for (const b of host.querySelectorAll('[data-seg]')) b.classList.toggle('on', b === seg);
    for (const p of host.querySelectorAll('[data-pane]')) {
      p.style.display = p.getAttribute('data-pane') === key ? '' : 'none';
    }
    return;
  }

  const cs = t.closest('[data-cs]');
  if (cs) {
    const c = chainOf(cs.getAttribute('data-cs'));
    if (!c) return;
    rt.chain = c;
    go({ id: 'acct', chain: c });
    return;
  }

  const open = t.closest('[data-open]');
  if (open) { openOvl(open.getAttribute('data-open')); return; }

  const check = t.closest('[data-check]');
  if (check) {
    check.querySelector('.cb')?.classList.toggle('on');
    const gateSel = check.getAttribute('data-check');
    const host = check.closest('.scr') ?? $view;
    const onCount = host.querySelectorAll(`[data-check="${gateSel}"] .cb.on`).length;
    for (const g of host.querySelectorAll(gateSel)) g.disabled = onCount === 0;
    return;
  }

  const copy = t.closest('[data-copy]');
  if (copy) { await doCopy(copy.getAttribute('data-copy')); return; }

  const actNode = t.closest('[data-act]');
  if (actNode) {
    const name = actNode.getAttribute('data-act');
    const fn = ACTS[name];
    if (!fn) { toast(`未实现的动作：${name}`); return; }
    actNode.disabled = true;
    try {
      await fn(actNode);
    } finally {
      if (actNode.isConnected) actNode.disabled = false;
    }
    return;
  }

  const tst = t.closest('[data-toast]');
  if (tst) { toast(tst.getAttribute('data-toast')); return; }
});

// 表单回车 = 该屏主操作（与各自主按钮同一个 data-act）。
$view.addEventListener('keydown', (e) => {
  if (e.key !== 'Enter') return;
  const n = e.target;
  if (!n || (n.tagName !== 'INPUT' && n.tagName !== 'TEXTAREA')) return;
  const primary = n.closest('.scr')?.querySelector('[data-enter="1"]');
  if (primary) { e.preventDefault(); primary.click(); }
});

// ---------------------------------------------------------------------------
// 头部与骨架
// ---------------------------------------------------------------------------

function layerKey(chain) {
  return chain === 'zc' ? 'zchain' : chain;
}

function layerOf(chain) {
  return (rt.overview?.layers ?? {})[layerKey(chain)] ?? { has: false, unlocked: false, address: null, label: null };
}

/** 金额显隐（公共场所；只影响展示，不参与任何计算）。 */
function amt(text) {
  return rt.hideAmount ? '••••' : text;
}

function walletLabel() {
  const L = rt.overview?.layers ?? {};
  return L.zchain?.label ?? L.evm?.label ?? L.stk?.label ?? '本钱包';
}

function anyUnlocked(ov) {
  const L = ov.layers ?? {};
  return Boolean(L.zchain?.unlocked || L.evm?.unlocked || L.stk?.unlocked);
}

/** 三链统一解锁计数。 */
function unlockCount(ov) {
  const L = ov.layers ?? {};
  const held = ['zchain', 'evm', 'stk'].filter((k) => L[k]?.has);
  return { held: held.length, unlocked: held.filter((k) => L[k]?.unlocked).length };
}

/** 票据抬头（两行 + 齿孔线）。 */
function docHeader({ kind, netText, netAct, addrText, sub, copySpec, lockAct = 'lock-current' }) {
  const top = h('div', { class: 'dh-top' }, [
    h('span', { class: 'dh-kind', text: kind }),
    netText
      ? h('button', { class: 'net', type: 'button', id: 'net-badge', 'data-act': netAct ?? '' }, [h('span', { class: 'dot' }), netText])
      : h('span', { class: 'grow' }),
    h('span', { class: 'dh-r' }, [
      iconBtn(rt.hideAmount ? 'eye-off' : 'eye', { bare: true, attrs: { 'data-act': 'toggle-amount', id: 'toggle-amount', title: rt.hideAmount ? '显示金额' : '隐藏金额' } }),
      iconBtn('gear', { bare: true, attrs: { 'data-nav': 'settings', id: 'hdr-settings', title: '设置' } }),
    ]),
  ]);
  const main = h('div', { class: 'dh-main' }, [
    h('span', { class: 'av', text: walletLabel().slice(0, 1).toUpperCase() }),
    h('div', { class: 'grow', style: 'min-width:0' }, [
      h('button', {
        class: 'acct-n', type: 'button', 'data-act': 'account-sheet', id: 'hdr-account',
        style: 'background:none;border:none;padding:0;font:inherit;cursor:pointer;width:100%',
      }, [h('span', { class: 'trunc', text: sub ?? walletLabel() }), ic('chev-d', 'ic ic-s')]),
      h('div', { class: 'acct-a', id: 'header-addr', text: addrText ?? '' }),
    ]),
    h('span', { class: 'dh-r' }, [
      copySpec ? iconBtn('copy', { attrs: { 'data-copy': copySpec, id: 'hdr-copy', title: '复制地址' } }) : null,
      lockAct ? iconBtn('lock', { attrs: { 'data-act': lockAct, id: 'hdr-lock', title: '锁定本层' } }) : null,
    ]),
  ]);
  return h('header', { class: 'dh' }, [top, main]);
}

/** 子页栏（细线 + 方形返回）。 */
function subHeader(title, { right = null, closeIcon = false } = {}) {
  return h('header', { class: 'sub' }, [
    iconBtn(closeIcon ? 'x' : 'back', { bare: true, attrs: { 'data-back': '1', id: 'sub-back', title: '返回' } }),
    h('div', { class: 'sub-t', text: title }),
    h('div', { class: 'sub-s' }, [right]),
  ]);
}

/** 底部三 tab（总账 / 账簿 / 证明）。 */
function tabsBar() {
  const cur = tabOf(rt.screen);
  const b = (id, nav, iconName, label) =>
    h('button', { class: `tb ${cur === id ? 'on' : ''}`.trim(), type: 'button', 'data-nav': nav, id: `tab-${id}` }, [ic(iconName), label]);
  return h('nav', { class: 'tabs' }, [
    b('home', 'home', 'home', '总账'),
    b('acct', `acct:${rt.chain}`, 'book', '账簿'),
    b('proofs', 'proofs', 'shield', '证明'),
  ]);
}

function scr(children, { aria = '' } = {}) {
  return h('section', { class: 'scr on', 'aria-label': aria }, children);
}

function body(children, { pb = false } = {}) {
  return h('div', { class: `body ${pb ? 'pb' : ''}`.trim() }, children);
}

/** 链切换器（账簿内链=筛选器，不是目的地）。 */
function chainSwitcher(counts = {}) {
  const b = (c, label) => h('button', {
    class: rt.chain === c ? 'on' : '', type: 'button', 'data-cs': c, id: `cs-${c}`,
  }, [label, counts[c] != null ? h('span', { class: 'cnt', text: String(counts[c]) }) : null]);
  return h('div', { class: 'csw' }, [b('zc', 'ZChain'), b('evm', 'EVM'), b('stk', 'Starknet')]);
}

/** 收款 sheet（三链共用；二维码编码器未接入 → 只给完整地址）。 */
function recvSheet(id, title, addr, subText) {
  const passId = `${id}-addr`;
  return h('div', { class: 'ovl', id }, [
    h('div', { class: 'ovl-bg', 'data-close': '1' }),
    h('div', { class: 'sheet' }, [
      h('div', { class: 'grab' }),
      h('div', { class: 'row' }, [
        h('div', { style: 'font-weight:600;font-size:13px;flex:1', text: title }),
        iconBtn('x', { bare: true, attrs: { 'data-close': '1' } }),
      ]),
      h('div', { style: 'margin-top:10px' }, [
        h('div', { class: 'mono', style: 'font-size:9.5px;color:var(--ink-3);word-break:break-all;margin-bottom:6px', text: subText ?? '' }),
        passBox(passId, addr, { copyTitle: '复制完整地址' }),
      ]),
      banner('info', '二维码未接入', '本版本没有经过验证的 QR 编码器：收款请复制上方完整地址核对后使用，界面不绘制无法保证正确的码图。'),
    ]),
  ]);
}

function mount(node) {
  $view.replaceChildren(node);
}

// ---------------------------------------------------------------------------
// 渲染主循环
// ---------------------------------------------------------------------------

const RENDERERS = {};

async function render() {
  const mySeq = ++rt.seq;
  try {
    const ov = await send({ type: 'popup:overview' });
    if (mySeq !== rt.seq) return;
    if (ov?.error) {
      const s = scr([body([errLine('render-err')])], { aria: '错误' });
      mount(s);
      setErr(s, ov.error);
      return;
    }
    rt.overview = ov;

    // 首屏路由：未 onboarding → 欢迎；三层全锁 → 统一解锁屏。
    if (!ov.onboarded && !['welcome', 'success', 'import'].includes(rt.screen)) rt.screen = 'welcome';
    if (ov.onboarded && rt.screen === 'welcome') rt.screen = 'home';
    if (ov.onboarded && !anyUnlocked(ov) && !['lock', 'import', 'settings'].includes(rt.screen)) rt.screen = 'lock';

    await (RENDERERS[rt.screen] ?? RENDERERS.home)(ov);
    if (mySeq !== rt.seq) return;
    applyGround();
    applyOvl();          // 浮层开合跨渲染保持
    ensureCapMatrix();   // 模态仍在打开时把按需内容补回新节点
    tickCountdowns();
  } finally {
    // 渲染代数计数：e2e 用它等待"新树渲染完成"（避免点击落在旧树上）。
    window.__zRenderGen = (window.__zRenderGen ?? 0) + 1;
  }
}

/** 倒计时心跳：只改 [data-countdown] 文本，不重渲染整屏。 */
function tickCountdowns() {
  for (const n of $view.querySelectorAll('[data-countdown]')) {
    const until = Number(n.getAttribute('data-countdown'));
    n.textContent = remainText(until - Date.now());
  }
}

setInterval(() => {
  if ($view.querySelector('[data-countdown]')) tickCountdowns();
}, 1000);

// ---------------------------------------------------------------------------
// 01 欢迎 · 一次创建三层
// ---------------------------------------------------------------------------

RENDERERS.welcome = async () => {
  mount(scr([
    h('div', { class: 'cover' }, [
      chip('DevNet', 'ch-solid'),
      logo('cv-logo', 'color:var(--ink)'),
      h('div', { class: 'cv-n', text: 'ZChain Wallet' }),
      h('div', { class: 'cv-t', text: '桌上飞快，结算可证' }),
      h('div', { class: 'cv-e', text: 'Fast at the table. Verifiable at settlement.' }),
      h('div', { class: 'cv-meta' }, [
        h('div', {}, [h('b', { text: '3' }), h('span', { text: '账户层' })]),
        h('div', {}, [h('b', { text: '2 套 KDF' }), h('span', { text: '本地加密' })]),
        h('div', {}, [h('b', { text: 'STARK' }), h('span', { text: '可复验' })]),
      ]),
      h('div', { class: 'row', style: 'gap:6px;margin-top:14px;flex-wrap:wrap' }, [
        h('span', { class: 'ch ch-felt' }, [ic('spade', 'ic ic-xs'), 'ZChain 隐私层']),
        h('span', { class: 'ch' }, [ic('ether', 'ic ic-xs'), 'EVM 多链']),
        h('span', { class: 'ch' }, [ic('layers', 'ic ic-xs'), 'Starknet']),
      ]),
      h('div', { class: 'cv-acts' }, [
        btn('一键创建钱包', { id: 'welcome-create-btn', icon: 'plus', attrs: { 'data-act': 'quick-create' } }),
        btn('导入或恢复钱包', { cls: 'btn-s', id: 'welcome-import-btn', attrs: { 'data-nav': 'import' } }),
        h('details', { id: 'welcome-advanced' }, [
          h('summary', { text: '高级：自定义解锁口令创建' }),
          field('自定义口令', input('welcome-pw', { type: 'password', placeholder: '≥ 8 位' })),
          field('确认口令', input('welcome-pw2', { type: 'password', placeholder: '再次输入' })),
          btn('用自定义口令创建', { cls: 'btn-s', id: 'welcome-custom-btn', attrs: { 'data-act': 'quick-create-custom' } }),
        ]),
        h('div', { class: 'hint-s', id: 'welcome-import', text: '一次创建三层账户：ZChain 隐私层 + EVM 多链 + Starknet' }),
      ]),
      errLine('welcome-err'),
    ]),
    h('div', { class: 'cv-foot', text: '继续即代表知悉测试网风险 · 口令不存储、不可找回 · MV3 DevNet 形态' }),
  ], { aria: '欢迎' }));
};

// ---------------------------------------------------------------------------
// 02 创建成功 · 解锁口令只显示一次
// ---------------------------------------------------------------------------

RENDERERS.success = async () => {
  const res = rt.created ?? {};
  const L = res.layers ?? {};
  mount(scr([body([
    h('div', { class: 'center', id: 'welcome-success', style: 'padding:22px 0 16px' }, [
      seal('已创建'),
      h('h1', { style: 'font-size:19px;margin:14px 0 4px', text: '钱包已创建' }),
      h('p', { style: 'color:var(--ink-2);font-size:12px', text: '三层账户已就绪，先保存好解锁口令。' }),
    ]),
    res.generated
      ? banner('bad', '解锁口令只显示这一次', '钱包不存储口令；丢失后仅能通过加密备份恢复。')
      : banner('info', '已使用你的自定义口令', '三层共用同一口令，但会话彼此独立、密钥各自派生。'),
    res.generated && res.password
      ? passBox('welcome-generated-password', res.password, { copyTitle: '复制口令' })
      : null,
    cd('三层地址', [
      lr('ZChain', shortAddr(L.zchain?.publicKey ?? '—'), { vKids: [h('span', { id: 'success-zc-addr', text: L.zchain?.publicKey ?? '—' }), iconBtn('copy', { bare: true, attrs: { 'data-copy': '#success-zc-addr' } })] }),
      lr('EVM', shortAddr(L.evm?.address ?? '—'), { vKids: [h('span', { id: 'success-evm-addr', text: L.evm?.address ?? '—' }), iconBtn('copy', { bare: true, attrs: { 'data-copy': '#success-evm-addr' } })] }),
      lr('Starknet', shortAddr(L.stk?.address ?? '—'), { vKids: [h('span', { id: 'success-stk-addr', text: L.stk?.address ?? '—' }), iconBtn('copy', { bare: true, attrs: { 'data-copy': '#success-stk-addr' } })] }),
    ]),
    chk('我已将口令保存在安全的地方（密码管理器 / 纸质备份）', { gate: 'start', id: 'welcome-done-gate', style: 'margin:2px 0 14px' }),
    btn('我已保存，开始使用', { cls: 'btn-p btn-lg', id: 'welcome-done-btn', disabled: true, attrs: { 'data-gated': 'start', 'data-act': 'welcome-done' } }),
    errLine('success-err'),
  ], { pb: true })], { aria: '创建成功' }));
};

// ---------------------------------------------------------------------------
// 03 导入 / 恢复（备份恢复 / 私钥导入）
// ---------------------------------------------------------------------------

RENDERERS.import = async () => {
  const s = scr([
    subHeader('导入 / 恢复'),
    body([
      h('div', { class: 'seg' }, [
        h('button', { class: 'on', type: 'button', 'data-seg': 'backup', id: 'imp-seg-backup', text: '备份恢复' }),
        h('button', { type: 'button', 'data-seg': 'key', id: 'imp-seg-key', text: '私钥导入' }),
      ]),
      h('div', { 'data-pane': 'backup' }, [
        h('label', { class: 'empty', style: 'display:block;padding:24px 14px;cursor:pointer' }, [
          ic('ul', 'ic'),
          h('b', { style: 'display:block;font-size:13px;color:var(--ink);margin:7px 0 3px', text: '选择 .zcbk 备份文件' }),
          h('span', { class: 'mono', style: 'font-size:10.5px', text: '由「设置 → 备份导出」生成 · 仅 ZChain 层 note 库' }),
          h('input', { type: 'file', id: 'backup-file', accept: '.zcbk,application/octet-stream', style: 'display:none' }),
        ]),
        h('div', { id: 'backup-file-name', class: 'mono', style: 'font-size:10.5px;color:var(--ink-3);margin:6px 0 10px' }),
        field('备份口令', input('backup-pw', { type: 'password', placeholder: '≥ 8 位，与钱包解锁口令相互独立' })),
        btn('恢复钱包', { id: 'backup-import-btn', attrs: { 'data-act': 'backup-import', 'data-enter': '1' } }),
        banner('info', '只覆盖 ZChain 层', 'ZCBK v1 含 REAL/PLAY 双库与 keystore 信封，不含 EVM / Starknet 账户——那两层请在「账户管理 → 导出私钥」后自行备份。解密全程本地完成，备份口令不离开设备。'),
      ]),
      h('div', { 'data-pane': 'key', style: 'display:none' }, [
        field('目标层', h('select', { id: 'import-layer' }, [
          h('option', { value: 'evm', text: 'EVM · secp256k1' }),
          h('option', { value: 'stk', text: 'Starknet · STARK curve' }),
        ])),
        field('私钥（hex）', input('import-key', { cls: 'mono', placeholder: '0x… 或裸 hex' })),
        field('加密口令', input('import-pw', { type: 'password', placeholder: '用于本地 keystore 加密（≥ 8 位）' })),
        btn('导入到所选层', { id: 'import-key-btn', attrs: { 'data-act': 'import-key' } }),
        h('p', { class: 'hint-s', style: 'text-align:left;margin-top:12px', text: 'ZChain note 层不支持私钥导入：note 库由 wallet-core 派生，只能经 .zcbk 备份恢复。' }),
      ]),
      errLine('import-err'),
      okLine('import-ok'),
    ]),
  ], { aria: '导入恢复' });
  mount(s);
  const f = document.getElementById('backup-file');
  f?.addEventListener('change', () => {
    const n = document.getElementById('backup-file-name');
    if (n) n.textContent = f.files?.[0] ? `已选择：${f.files[0].name}` : '';
  });
};

// ---------------------------------------------------------------------------
// 04 锁定 · 统一解锁（三层共用口令，会话彼此独立）
// ---------------------------------------------------------------------------

RENDERERS.lock = async (ov) => {
  const { held, unlocked } = unlockCount(ov);
  const pendingRes = await send({ type: 'popup:listPending' });
  const pending = pendingRes?.pending ?? [];
  const addr = layerOf(rt.chain).address ?? ov.layers?.zchain?.address ?? '';
  mount(scr([
    h('div', { class: 'cover', style: 'justify-content:center;align-items:center;text-align:center' }, [
      h('span', { class: 'av', style: 'width:52px;height:52px;font-size:19px', text: walletLabel().slice(0, 1).toUpperCase() }),
      h('div', { style: 'font-size:16px;font-weight:700;margin-top:12px', text: walletLabel() }),
      h('div', { class: 'mono', style: 'font-size:11px;color:var(--ink-3);margin-top:2px', text: shortAddr(addr) }),
      h('div', { class: 'row', style: 'gap:6px;margin-top:12px;justify-content:center;flex-wrap:wrap' }, [
        chip('已锁定', 'ch-amb'),
        chip(`已解锁 ${unlocked} / ${held}`),
        pending.length > 0 ? chip(`${pending.length} 项待确认`, 'ch-bad') : null,
      ]),
      h('div', { style: 'width:100%;max-width:282px;margin-top:22px' }, [
        input('home-unlock-pw', { type: 'password', placeholder: '解锁口令' }),
        btn('解锁三层', { id: 'home-unlock-btn', attrs: { 'data-act': 'quick-unlock', 'data-enter': '1', style: 'margin-top:10px' } }),
        pending.length > 0
          ? btn(`查看 ${pending.length} 项待确认`, { cls: 'btn-s', id: 'lock-pending', attrs: { 'data-nav': 'zc-confirm', style: 'margin-top:4px' } })
          : btn('忘记口令？使用备份恢复', { cls: 'btn-g', id: 'lock-import', attrs: { 'data-nav': 'import', style: 'margin-top:4px' } }),
        errLine('lock-err'),
      ]),
    ]),
    h('div', { class: 'cv-foot', text: '统一解锁三层 · ZChain 层 Argon2id + ChaCha20-Poly1305，EVM / Starknet 层 PBKDF2-SHA256(600k) + AES-256-GCM' }),
  ], { aria: '解锁' }));
};

// ---------------------------------------------------------------------------
// 05 三链总账（首页）
// ---------------------------------------------------------------------------

RENDERERS.home = async (ov) => {
  const L = ov.layers ?? {};
  const { held, unlocked } = unlockCount(ov);
  const [notesRes, receiptsRes, pendingRes] = await Promise.all([
    L.zchain?.unlocked ? send({ type: 'popup:getNotes' }) : Promise.resolve(null),
    send({ type: 'popup:receipts' }),
    send({ type: 'popup:listPending' }),
  ]);
  const notes = notesRes && !notesRes?.error ? notesRes : null;
  const g = notes ? groupBalances(notes.balances ?? {}) : null;
  const receipts = receiptsRes?.receipts ?? [];
  const pending = pendingRes?.pending ?? [];
  const realLadder = notes ? proofLadder(notes.realNotes ?? []) : null;

  const hero = h('div', { class: 'tot' }, [
    h('div', { class: 'tot-l' }, ['三链总资产', PRICE_SOURCE_CONNECTED ? null : chip('价格源未接入', 'ch-xs')]),
    h('div', { class: 'tot-a' }, [PRICE_SOURCE_CONNECTED ? '$0.00' : '—']),
    h('div', { class: 'tot-s' }, [
      chip(`已解锁 ${unlocked} / ${held}`, 'ch-felt'),
      h('span', { text: 'PLAY 为测试筹码不计价；REAL 为托管映射' }),
    ]),
  ]);

  const layerRow = (chain, { iconName, tkCls, name, desc, address, unlockedFlag }) => h('button', {
    class: 'ar', type: 'button', 'data-nav': `acct:${chain}`, id: `home-${chain}`,
    style: 'border:none;cursor:pointer;background:none;width:100%',
  }, [
    h('span', { class: `tk ${tkCls}`.trim() }, [ic(iconName, 'ic ic-s')]),
    h('div', { class: 'ar-m' }, [
      h('div', { class: 'ar-n' }, [name, chip(unlockedFlag ? '已解锁' : '已锁定', unlockedFlag ? 'ch-felt ch-xs' : 'ch-amb ch-xs')]),
      h('div', { class: 'ar-s', text: desc }),
    ]),
    h('div', { class: 'ar-r' }, [
      h('div', { class: 'ar-amt dim', text: unlockedFlag ? '进入账簿' : '需解锁' }),
      h('div', { class: 'ar-s mono', style: 'text-align:right', text: shortAddr(address ?? '未创建') }),
    ]),
  ]);

  const weakest = realLadder?.weakest ?? null;
  const steps = ladderSteps({ current: weakest, outcome: weakest && weakest !== 'finalized' ? 'wait' : 'ok' });

  mount(scr([
    docHeader({
      kind: 'General Ledger',
      netText: 'zchain-devnet-1',
      netAct: 'network-sheet',
      addrText: `三层统一账户 · 已解锁 ${unlocked} / ${held}`,
      lockAct: 'lock-all',
    }),
    body([
      hero,
      secT('账户层'),
      cd(null, [
        layerRow('zc', {
          iconName: 'spade', tkCls: 'tk-felt', name: 'ZChain 隐私层',
          desc: g ? amt(`PLAY ${fmtAmount(g.game.play.free)} · NATIVE ${fmtAmount(g.real.native.free)}`) : '解锁后显示分库余额',
          address: L.zchain?.address, unlockedFlag: L.zchain?.unlocked,
        }),
        layerRow('evm', {
          iconName: 'ether', tkCls: '', name: 'EVM 多链',
          desc: rt.evmInfo ? amt(`${fmtAmount(rt.evmInfo.balanceHuman)} ETH · chainId ${rt.evmInfo.chainIdHex}`) : '解锁后可查询链上余额',
          address: L.evm?.address, unlockedFlag: L.evm?.unlocked,
        }),
        layerRow('stk', {
          iconName: 'layers', tkCls: '', name: 'Starknet',
          desc: rt.stkInfo ? amt(`${fmtAmount(rt.stkInfo.balanceHuman)} ${rt.stkInfo.tokenSymbol ?? ''}`) : '解锁后可查询链上余额',
          address: L.stk?.address, unlockedFlag: L.stk?.unlocked,
        }),
      ], { cls: 'rows', id: 'home-card' }),
      cd('最弱凭证', [
        rail(steps, {
          capLeft: notes
            ? (realLadder?.total
              ? h('span', {}, [`${realLadder.total} 张 REAL note，短板 `, h('b', { style: `color:var(--${weakest === 'finalized' ? 'felt' : 'amb'})`, text: weakest })])
              : h('span', { text: '暂无 REAL note（0.x 不开放入金 / 铸造）' }))
            : h('span', { text: '解锁 ZChain 层后可见' }),
          capRight: btn('凭证簿', { cls: 'btn-s btn-sm', attrs: { 'data-nav': 'proofs', id: 'home-weak-view' } }),
        }),
      ]),
      cd('待办', pending.length === 0
        ? [emptyBox('无待确认请求')]
        : pending.slice(0, 3).map((p) => mi({
          iconName: p.kind === 'connect' ? 'people' : p.kind === 'switch_network' ? 'swap' : 'pen',
          icStyle: 'color:var(--amb);border-color:var(--amb-rl);background:var(--amb-w)',
          title: pendingTitle(p),
          sub: `${p.origin} · ${remainText((p.expiresAt ?? 0) - Date.now())} 后过期`,
          attrs: { 'data-nav': 'zc-confirm', id: 'home-pending-item' },
        })), { more: `${pending.length} 项`, moreAttrs: { 'data-nav': 'zc-confirm', id: 'home-pending-more' } }),
      receipts.length > 0
        ? cd('最近回执', receipts.slice(0, 2).map((r) => {
          const c = receiptChip(r);
          return txRow({
            iconName: r.status === 'included' ? 'check' : r.status === 'seen' ? 'receipt' : 'clock',
            ticCls: r.status === 'included' ? 'ok' : r.status === 'seen' ? 'blue' : 'warn',
            name: kindLabel(r.kind),
            sub: `${shortAddr(r.digest, 8, 6)} · ${relTime(r.signedAtMs)}`,
            chipNode: chip(c.text, `ch-xs ${c.cls}`),
          });
        }), { more: '查看全部', moreAttrs: { 'data-nav': 'zc-receipts', id: 'home-receipts-more' } })
        : null,
      btn('全部锁定', { cls: 'btn-s', id: 'home-lock-all', attrs: { 'data-act': 'lock-all', style: 'width:100%;height:38px;margin-top:2px' }, icon: 'lock' }),
      h('div', { class: 'foot', text: `ZChain Wallet · 方向 B 账簿 v0.2 / Extension ${ov.providerVersion ?? ''} · DevNet` }),
    ]),
    tabsBar(),
  ], { aria: '三链总账' }));
};

function kindLabel(kind) {
  return { transfer: '转账', buy_in: '买入', settle: '结算', withdraw: '提现' }[kind] ?? String(kind ?? '操作');
}

function pendingTitle(p) {
  if (p.kind === 'connect') return '连接请求';
  if (p.kind === 'switch_network') return '网络切换请求';
  return `${kindLabel(p.preview?.kind)}签名请求`;
}

// ---------------------------------------------------------------------------
// 通用动作（跨屏幕共享）
// ---------------------------------------------------------------------------

act('toggle-amount', () => {
  rt.hideAmount = !rt.hideAmount;
  persistPrefs();
  render();
});

act('quick-create', async () => {
  const res = await send({ type: 'popup:quickCreate' });
  if (res?.error) { setErr(document.getElementById('welcome-advanced')?.closest('.scr'), res.error); toast(errorText(res.error)); return; }
  rt.created = res;
  rt.screen = 'success';
  render();
});

act('quick-create-custom', async () => {
  const p1 = document.getElementById('welcome-pw')?.value ?? '';
  const p2 = document.getElementById('welcome-pw2')?.value ?? '';
  if (p1.length < 8) { toast('口令太短（≥ 8 字符）'); return; }
  if (p1 !== p2) { toast('两次口令不一致'); return; }
  const res = await send({ type: 'popup:quickCreate', password: p1 });
  document.getElementById('welcome-pw').value = '';
  document.getElementById('welcome-pw2').value = '';
  if (res?.error) { toast(errorText(res.error)); return; }
  rt.created = { ...res, generated: false };
  rt.screen = 'success';
  render();
});

act('welcome-done', () => {
  rt.created = null;
  rt.screen = 'home';
  render();
});

act('quick-unlock', async () => {
  const scope = currentScr();
  const pw = document.getElementById('home-unlock-pw');
  clearErr(scope);
  if (!pw?.value) { setErr(scope, null, '请输入解锁口令'); return; }
  const res = await send({ type: 'popup:quickUnlock', password: pw.value });
  pw.value = ''; // 口令不驻留 DOM
  if (res?.error) { setErr(scope, res.error); return; }
  if (!res.unlockedCount) { setErr(scope, null, '口令错误（fail-closed）'); return; }
  if (res.results && Object.values(res.results).some((v) => v === false)) {
    toast(`已解锁 ${res.unlockedCount} / ${res.total} 层：其余层口令与本层不同，可分别解锁`);
  }
  rt.screen = 'home';
  render();
});

act('lock-current', async () => {
  const chain = rt.chain;
  if (chain === 'evm') { await send({ type: 'popup:evmLock' }); rt.evmInfo = null; }
  else if (chain === 'stk') { await send({ type: 'popup:stkLock' }); rt.stkInfo = null; }
  else await send({ type: 'popup:lock' });
  rt.screen = 'lock';
  render();
});

act('lock-all', async () => {
  await send({ type: 'popup:lockAll' });
  rt.evmInfo = null;
  rt.stkInfo = null;
  rt.screen = 'lock';
  render();
});

act('import-key', async () => {
  const scope = currentScr();
  clearErr(scope);
  const layer = document.getElementById('import-layer').value;
  const res = await send({
    type: layer === 'stk' ? 'popup:stkImportKey' : 'popup:evmImportKey',
    privateKey: document.getElementById('import-key').value.trim(),
    password: document.getElementById('import-pw').value,
  });
  document.getElementById('import-key').value = '';
  document.getElementById('import-pw').value = '';
  if (res?.error) { setErr(scope, res.error); return; }
  rt.chain = layer;
  const ok = document.getElementById('import-ok');
  if (ok) ok.textContent = `已导入 ${CHAIN_LABEL[layer]} 账户 ${shortAddr(res.address ?? '')}（锁定态，需口令解锁）。`;
  toast('导入成功：已新增账户（锁定态）');
});

act('backup-import', async () => {
  const scope = currentScr();
  clearErr(scope);
  const f = document.getElementById('backup-file');
  const file = f?.files?.[0];
  if (!file) { setErr(scope, null, '请选择 .zcbk 备份文件'); return; }
  const buf = new Uint8Array(await file.arrayBuffer());
  let hex = '';
  for (const b of buf) hex += b.toString(16).padStart(2, '0');
  const res = await send({ type: 'popup:backupImport', backupHex: hex, password: document.getElementById('backup-pw').value });
  document.getElementById('backup-pw').value = '';
  if (f) f.value = '';
  if (res?.error) { setErr(scope, res.error); return; }
  const ok = document.getElementById('import-ok');
  if (ok) ok.textContent = `恢复完成：新增锁定账户（${res.indexes?.commitments ?? 0} commitments / ${res.indexes?.nullifiers ?? 0} nullifiers）。用备份口令解锁该账户即可使用。`;
  toast('恢复成功：新账户为锁定态');
});

/** 账户切换 sheet（当前链的账户列表；切换即锁定该层会话）。 */
act('account-sheet', async () => {
  const chain = rt.chain;
  const type = chain === 'evm' ? 'popup:evmGetState' : chain === 'stk' ? 'popup:stkGetState' : 'popup:getState';
  const st = await send({ type });
  if (st?.error) { toast(errorText(st.error)); return; }
  const accounts = (st.accounts ?? []).map((a) => ({
    id: a.id, label: a.label, addr: chain === 'zc' ? (a.publicKey ?? '（解锁后可见）') : a.address,
    unlocked: a.unlocked, active: a.active ?? (chain === 'zc' ? a.id === st.activeAccountId : a.active),
  }));
  const selType = chain === 'evm' ? 'popup:evmSelectAccount' : chain === 'stk' ? 'popup:stkSelectAccount' : 'popup:selectAccount';
  openSheetNode(`${CHAIN_LABEL[chain]} 账户切换`, [
    ...accounts.map((a) => h('button', {
      class: `al ${a.active ? 'on' : ''}`.trim(), type: 'button', 'data-act': 'select-account',
      'data-id': a.id, 'data-chain': chain, 'data-type': selType, id: `acct-${a.id}`,
    }, [
      h('span', { class: 'av', text: (a.label ?? 'A').slice(0, 1).toUpperCase() }),
      h('span', { class: 'grow', style: 'min-width:0' }, [
        h('span', { style: 'display:block;font-weight:600;font-size:12.5px' }, [a.label ?? '未命名', a.active ? chip('当前', 'ch-felt ch-xs') : null]),
        h('span', { class: 'al-a', text: shortAddr(a.addr ?? '') }),
      ]),
      chip(a.unlocked ? '已解锁' : '锁定中', a.unlocked ? 'ch-felt ch-xs' : 'ch-amb ch-xs'),
    ])),
    accounts.length === 0 ? emptyBox('本层暂无账户') : null,
    btn('新建 / 导入账户', { cls: 'btn-s', attrs: { 'data-nav': 'import', id: 'acct-sheet-import', style: 'margin-top:12px' } }),
    h('p', {
      class: 'hint-s', style: 'margin-top:8px;text-align:left',
      text: chain === 'zc'
        ? '切换账户会锁定当前 ZChain 会话（wasm 单槽）；其他账户的密文互不影响。'
        : '切换即锁定本层会话，目标账户需口令解锁。',
    }),
  ]);
});

act('select-account', async (node) => {
  const chain = node.getAttribute('data-chain');
  const res = await send({ type: node.getAttribute('data-type'), accountId: node.getAttribute('data-id') });
  if (res?.error) { toast(errorText(res.error)); return; }
  if (chain === 'evm') rt.evmInfo = null;
  if (chain === 'stk') rt.stkInfo = null;
  closeAllSheets();
  toast('已切换账户（锁定态，需口令解锁）');
  rt.screen = 'lock';
  render();
});

function networkRow(chain, id, name, sub, current) {
  return mi({
    iconName: current ? 'check' : 'swap',
    title: name,
    sub: `${sub}${current ? ' · 当前' : ''}`,
    right: current ? chip('当前', 'ch-felt ch-xs') : null,
    attrs: { 'data-act': 'set-network', 'data-id': id, 'data-chain': chain, id: `net-${chain}-${id}` },
  });
}

/** 网络选择 sheet（三链；devnet/testnet 封闭注册表，mainnet 刻意不在）。 */
act('network-sheet', async () => {
  const chain = rt.chain;
  if (chain === 'zc') {
    const st = await send({ type: 'popup:getState' });
    openSheetNode('ZChain 网络', [
      ...((st.networks ?? []).map((id) => networkRow('zc', id, id === 'zchain-devnet-1' ? '开发网（本地）' : '测试网', id, id === st.chainId))),
      h('p', { class: 'hint-s', style: 'text-align:left', text: 'mainnet 不在注册表内：跨网请求一律 NetworkUnsupported，不隐藏、不放行。' }),
    ]);
    return;
  }
  const st = await send({ type: chain === 'evm' ? 'popup:evmGetState' : 'popup:stkGetState' });
  const nets = (st.networks ?? []).map((n) => networkRow(
    chain, n.id, n.name, chain === 'evm' ? n.chainIdHex : n.chainId, n.id === st.networkId,
  ));
  openSheetNode(`${CHAIN_LABEL[chain]} 网络`, [
    ...nets,
    h('p', {
      class: 'hint-s', style: 'text-align:left',
      text: chain === 'evm'
        ? '切换即改 RPC 与 explorer 口径；RPC 返回的 chainId 与预设不符时如实告警，不静默继续。'
        : '账户地址由 (class hash, salt, pubkey) 推导：class hash 换档即换地址，如实标注。',
    }),
  ]);
});

act('set-network', async (node) => {
  const chain = node.getAttribute('data-chain');
  const id = node.getAttribute('data-id');
  const type = chain === 'evm' ? 'popup:evmSetNetwork' : chain === 'stk' ? 'popup:stkSetNetwork' : 'popup:switchNetwork';
  const res = await send({ type, ...(chain === 'zc' ? { chainId: id } : { networkId: id }) });
  if (res?.error) { toast(errorText(res.error)); return; }
  if (chain === 'evm') rt.evmInfo = null;
  if (chain === 'stk') rt.stkInfo = null;
  closeAllSheets();
  toast('网络已切换');
  render();
});

act('refresh-evm', async () => {
  const res = await send({ type: 'popup:evmRefresh' });
  if (res?.error) { toast(errorText(res.error)); return; }
  rt.evmInfo = res;
  render();
});

act('refresh-stk', async () => {
  const res = await send({ type: 'popup:stkRefresh' });
  if (res?.error) { toast(errorText(res.error)); return; }
  rt.stkInfo = res;
  render();
});

// ---------------------------------------------------------------------------
// 06 账簿 · 一份结构 × 三链数据面（方向 B 的结构性主张）
// ---------------------------------------------------------------------------

RENDERERS.acct = async (ov) => {
  const chain = rt.chain;
  const L = layerOf(chain);
  const pane = chain === 'zc' ? await zcPane(ov) : chain === 'evm' ? await evmPane(ov) : await stkPane(ov);
  const counts = {
    zc: L.has ? 2 : 0,
    evm: (ov.layers?.evm?.accounts ?? null) ?? (ov.layers?.evm?.has ? 1 : 0),
    stk: (ov.layers?.stk?.accounts ?? null) ?? (ov.layers?.stk?.has ? 1 : 0),
  };
  mount(scr([
    docHeader({
      kind: `Ledger · ${chain === 'zc' ? 'Zchain' : chain === 'evm' ? 'Evm' : 'Starknet'}`,
      netText: pane.netText,
      netAct: 'network-sheet',
      addrText: shortAddr(L.address ?? '未创建', 12, 8),
      copySpec: L.address ? `#header-addr` : null,
    }),
    body([chainSwitcher(counts), ...pane.nodes, pane.sheets]),
    tabsBar(),
  ], { aria: '账簿' }));
};

/** ZChain 层数据面（GAME/REAL 分库 + 凭证阶梯 + 会话密钥摘要）。 */
async function zcPane(ov) {
  const unlocked = ov.layers?.zchain?.unlocked;
  if (!unlocked) {
    return {
      netText: 'zchain-devnet-1',
      nodes: [
        banner('amb', '本层已锁定', '解锁后才能查看分库余额与 note 明细；锁定态不缓存任何明文。'),
        btn('解锁 ZChain 层', { cls: 'btn-s', id: 'zc-goto-lock', attrs: { 'data-nav': 'lock' } }),
      ],
      sheets: null,
    };
  }
  const [notesRes, viewsRes, receiptsRes, regRes, stRes] = await Promise.all([
    send({ type: 'popup:getNotes' }),
    send({ type: 'popup:getDisplayViews' }),
    send({ type: 'popup:receipts' }),
    send({ type: 'popup:getRegistry' }),
    send({ type: 'popup:getState' }),
  ]);
  if (notesRes?.error) {
    return { netText: stRes?.chainId ?? 'zchain-devnet-1', nodes: [errLine('zc-err')], sheets: null };
  }
  const g = groupBalances(notesRes.balances ?? {});
  const real = viewsRes?.real ?? {};
  const receipts = (receiptsRes?.receipts ?? []).slice(0, 2);
  const sessions = regRes?.sessionKeys ?? [];
  const gov = sessions.find((b) => b.status === 'active') ?? sessions[0] ?? null;
  const usage = gov ? sessionUsage(gov) : null;

  const split = h('div', { class: 'split' }, [
    h('div', { class: 'col' }, [
      h('div', { class: 'tot-l' }, [chip('GAME', 'ch-play ch-xs'), '可用筹码']),
      h('div', { class: 'tot-a' }, [amt(fmtAmount(g.game.play.free)), h('span', { class: 'u', text: 'PLAY' })]),
    ]),
    h('div', { class: 'col' }, [
      h('div', { class: 'tot-l' }, [chip('REAL', 'ch-real ch-xs'), '托管映射']),
      h('div', { class: 'tot-a', style: 'color:var(--real)' }, [amt(fmtAmount(g.real.native.free)), h('span', { class: 'u', text: 'NATIVE' })]),
    ]),
  ]);

  const acts = h('div', { class: 'acts' }, [
    h('button', { class: 'play', type: 'button', 'data-open': 'ovl-zc-recv', id: 'zc-recv' }, [ic('qr'), '收款']),
    h('button', { type: 'button', 'data-nav': 'zc-send', id: 'zc-send' }, [ic('send'), '转账']),
    h('button', { class: 'real', type: 'button', 'data-nav': 'zc-withdraw', id: 'zc-withdraw' }, [ic('out'), '提现']),
    h('button', { type: 'button', 'data-nav': 'zc-portal', id: 'zc-portal' }, [ic('shield'), 'Portal']),
  ]);

  const assetCard = cd('资产', [
    assetRow({
      tk: 'P', tkCls: 'tk-play', name: 'PLAY', nameKids: [chip('GAME', 'ch-play ch-xs')],
      sub: `可用 ${fmtAmount(g.game.play.free)} · 桌上锁定 ${fmtAmount(g.game.play.locked)}`,
      amount: amt(fmtAmount(g.game.play.free)),
    }),
    assetRow({
      tk: 'N', tkCls: 'tk-real', name: 'NATIVE', nameKids: [chip('REAL', 'ch-real ch-xs')],
      sub: '托管映射 · 提现通道未开放',
      amount: amt(fmtAmount(g.real.native.free)),
    }),
    assetRow({ tk: 'U', name: 'USDT / USDC', sub: '未接入', amount: '—', amountCls: 'dim', attrs: { style: 'opacity:.55' } }),
  ], { more: '回执', moreAttrs: { 'data-nav': 'zc-receipts', id: 'zc-assets-more' } });

  const noteCard = cd('note 明细（脱敏）', [
    notesTable(notesRes.notes, 'GAME'),
    notesTable(notesRes.realNotes, 'REAL'),
    h('p', { class: 'hint-s', style: 'text-align:left;margin-top:6px', text: '无 spend secret / nullifier：脱敏字段由后台 sanitizeNotesForPage 统一裁切。' }),
  ]);

  const newsCard = cd('最新动态', receipts.length === 0
    ? [emptyBox('暂无回执（签名成功后登记）')]
    : receipts.map((r) => {
      const c = receiptChip(r);
      return txRow({
        iconName: r.status === 'included' ? 'check' : r.status === 'seen' ? 'receipt' : 'clock',
        ticCls: r.status === 'included' ? 'ok' : r.status === 'seen' ? 'blue' : 'warn',
        name: kindLabel(r.kind),
        sub: `${shortAddr(r.digest, 8, 6)} · ${relTime(r.signedAtMs)}`,
        chipNode: chip(c.text, `ch-xs ${c.cls}`),
      });
    }), { more: '查看全部', moreAttrs: { 'data-nav': 'zc-receipts', id: 'zc-news-more' } });

  const sessionCard = cd('会话密钥 · SNIP-12', gov
    ? [
      lr('origin', gov.origin),
      lr('单笔 / 日累计', `${gov.perTxLimit ?? '不限'} · ${usage.usedText}/${usage.limitText}`),
      usage.percent !== null ? meter(usage.percent, { warn: usage.exhausted, style: 'margin-top:8px' }) : null,
      lr('状态', sessionStatusChip(gov.status).text, { dim: false }),
    ]
    : [emptyBox('暂无授权：由 dapp 连接时按需建立')],
  { more: '管理', moreAttrs: { 'data-nav': 'zc-sessions', id: 'zc-session-more' } });

  const faucet = stRes?.networkKind === 'devnet'
    ? cd('devnet 水龙头（本地 stub，仅测试）', [
      field('铸造金额（PLAY）', input('faucet-amount', { type: 'text', value: '500', cls: 'mono', attrs: { inputmode: 'numeric' } })),
      btn('铸造 PLAY note', { cls: 'btn-s', id: 'zc-faucet-btn', attrs: { 'data-act': 'faucet' } }),
      h('p', { class: 'hint-s', style: 'text-align:left', text: '测试筹码：无真实价值、不上主网、不可赎回。' }),
    ])
    : null;

  const gate = cd('REAL 操作面', [
    lr('claim / 提现', real.show_claim ? '开放' : '未开放（不暗示可提现）'),
    real.claim_disabled_reason ? lr('原因', real.claim_disabled_reason, { dim: true }) : null,
    h('p', { class: 'hint-s', style: 'text-align:left;margin-top:8px', text: 'finality 以 note 的凭证层级展示（pending → soft → proven → finalized）；本界面不对 REAL 提供任何转账或兑换操作。' }),
  ]);

  const nodes = [
    split,
    banner('real', '托管映射资产', real.custody_risk_notice ?? 'REAL 域由运营方托管映射；GAME 域筹码不上主网。'),
    acts,
    assetCard,
    newsCard,
    sessionCard,
    faucet,
    gate,
    noteCard,
    h('div', { class: 'foot', text: '链=筛选器：三链共用同一账簿结构，只换数据面' }),
  ];
  return {
    netText: stRes?.chainId ?? 'zchain-devnet-1',
    nodes,
    sheets: recvSheet('ovl-zc-recv', '收款 · ZChain 层', stRes?.publicKey ?? '', `${stRes?.chainId ?? ''} · 公钥即 owner（hex33 压缩公钥）`),
  };
}

function notesTable(notes, domain) {
  const list = notes ?? [];
  const rows = [h('div', { class: 'cd-h' }, [`${domain} note`, list.length ? chip(String(list.length), 'ch-xs') : null])];
  if (list.length === 0) {
    rows.push(h('div', { class: 'ar-s', style: 'padding:6px 0', text: domain === 'REAL' ? '暂无 REAL note（0.x 不开放入金 / 铸造）' : '暂无 note（用水龙头铸造测试 PLAY）' }));
  }
  for (const n of list.slice(0, 12)) {
    const b = assetBadge(domain);
    rows.push(txRow({
      iconName: n.spendable ? 'check' : 'lock',
      ticCls: n.spendable ? 'ok' : 'warn',
      name: `${fmtAmount(n.amount)} ${b.tokenLabel ?? domain}`,
      sub: `${shortAddr(n.commitment ?? '', 8, 6)} · ${n.proof ?? 'pending'}`,
      chipNode: chip(n.spendable ? '可用' : '锁定', n.spendable ? 'ch-felt ch-xs' : 'ch-amb ch-xs'),
    }));
  }
  return h('div', { style: 'margin-bottom:10px' }, rows);
}

act('faucet', async () => {
  const v = (document.getElementById('faucet-amount')?.value ?? '').trim();
  if (!/^\d+$/.test(v) || BigInt(v) === 0n) { toast('金额必须是正整数'); return; }
  const res = await send({ type: 'popup:faucet', amount: v });
  if (res?.error) { toast(errorText(res.error)); return; }
  toast(`已铸造 ${fmtAmount(v)} PLAY`);
  render();
});

/** EVM 层数据面。 */
async function evmPane(ov) {
  const st = await send({ type: 'popup:evmGetState' });
  if (st?.error) return { netText: 'EVM', nodes: [errLine('evm-err')], sheets: null };
  const net = (st.networks ?? []).find((n) => n.id === st.networkId);
  const info = rt.evmInfo;
  if (!st.unlocked) return chainAccessPane('evm', st, net);
  const hist = await send({ type: 'popup:evmHistory', includeExplorer: false });
  const txs = (hist?.txs ?? []).slice(0, 3);
  return {
    netText: `${net?.name ?? 'EVM'} · ${net?.chainIdHex ?? ''}`,
    nodes: [
      chainBalanceTot('evm', info ? fmtAmount(info.balanceHuman) : '—', 'ETH', st.address, [
        info ? lr('折合', '价格源未接入', { dim: true }) : null,
      ]),
      chainActs('evm'),
      cd('网络', [
        h('div', { id: 'evm-chain-info' }, [
          lr('chainId', info ? info.chainIdHex : (net?.chainIdHex ?? '—'), { vKids: [h('span', { class: 'mono', text: `${info ? info.chainIdHex : (net?.chainIdHex ?? '—')} · ` }), chip(info ? (info.chainIdMismatch ? '与预设不符' : '校验通过') : '未查询', info ? (info.chainIdMismatch ? 'ch-bad' : 'ch-felt') : 'ch-xs')] }),
          lr('gas', info ? `${fmtAmount(info.gasPriceGwei)} gwei` : '—'),
          lr('nonce', info ? info.nonce : '—'),
          lr('RPC', net?.rpcUrl ?? '—'),
        ]),
        h('div', { class: 'btn-row', style: 'margin-top:10px' }, [
          btn(info ? '重新查询' : '查询余额 / nonce / gas', { cls: 'btn-s btn-sm', id: 'evm-refresh-btn', attrs: { 'data-act': 'refresh-evm', style: 'width:100%' } }),
        ]),
        info?.chainIdMismatch ? banner('bad', 'RPC 返回的 chainId 与网络预设不符', '已如实标注：签名会用预设 chainId 参与 EIP-155，请确认 RPC 指向正确网络。') : null,
      ]),
      net?.faucet ? cd('devnet 水龙头（测试链，无真实价值）', [
        field('领取金额（ETH）', input('evm-faucet-amount', { type: 'text', value: '1', cls: 'mono', attrs: { inputmode: 'decimal' } })),
        btn('领取 ETH', { cls: 'btn-s', id: 'evm-faucet-btn', attrs: { 'data-act': 'evm-faucet' } }),
        errLine('evm-faucet-err'),
        h('p', { class: 'hint-s', style: 'text-align:left', text: '开发链内置出资端点：仅在 devnet 生效，不用于任何真实资产。' }),
      ]) : null,
      cd('资产', [
        assetRow({ tk: 'Ξ', name: 'ETH', sub: '原生币', amount: info ? amt(fmtAmount(info.balanceHuman)) : '—', amountCls: info ? '' : 'dim' }),
        assetRow({ tk: 'T', name: 'ERC-20', sub: '需在「合约」页按代币地址读取', amount: '—', amountCls: 'dim', attrs: { style: 'opacity:.6' } }),
      ]),
      cd('最新动态', txs.length === 0 ? [emptyBox(hist?.error ? errorText(hist.error) : '暂无交易记录')] : txs.map(chainTxRow),
        { more: '查看全部', moreAttrs: { 'data-nav': 'history:evm', id: 'evm-news-more' } }),
      chainManageCard('evm', st),
    ],
    sheets: recvSheet('ovl-evm-recv', '收款 · EVM 层', st.address, `${net?.name ?? ''} · chainId ${net?.chainIdHex ?? ''}`),
  };
}

/** Starknet 层数据面。 */
async function stkPane(ov) {
  const st = await send({ type: 'popup:stkGetState' });
  if (st?.error) return { netText: 'Starknet', nodes: [errLine('stk-err')], sheets: null };
  const net = (st.networks ?? []).find((n) => n.id === st.networkId);
  const info = rt.stkInfo;
  if (!st.unlocked) return chainAccessPane('stk', st, net);
  const hist = await send({ type: 'popup:stkHistory', includeExplorer: false });
  const txs = (hist?.txs ?? []).slice(0, 3);
  return {
    netText: `${net?.name ?? 'Starknet'} · ${net?.chainId ?? ''}`,
    nodes: [
      chainBalanceTot('stk', info ? fmtAmount(info.balanceHuman) : '—', info?.tokenSymbol ?? 'ETH', st.address, []),
      chainActs('stk'),
      cd('网络', [
        h('div', { id: 'stk-chain-info' }, [
          lr('chainId', net?.chainId ?? '—', { vKids: [h('span', { class: 'mono', text: `${net?.chainId ?? '—'} · ` }), chip(info ? (info.chainIdMismatch ? '与预设不符' : '校验通过') : '未查询', info ? (info.chainIdMismatch ? 'ch-bad' : 'ch-felt') : 'ch-xs')] }),
          lr('nonce', info ? info.nonce : '—'),
          lr('账户地址', shortAddr(st.address ?? '', 10, 8)),
          lr('公钥', '', { vKids: [h('span', { class: 'mono', id: 'stk-pubkey', text: (st.accounts ?? []).find((a) => a.id === st.activeAccountId)?.pubKey ?? '—' })] }),
        ]),
        h('div', { class: 'btn-row', style: 'margin-top:10px' }, [
          btn(info ? '重新查询' : '查询余额 / nonce', { cls: 'btn-s btn-sm', id: 'stk-refresh-btn', attrs: { 'data-act': 'refresh-stk', style: 'width:100%' } }),
        ]),
      ]),
      cd('资产', [
        assetRow({ tk: 'Ξ', name: info?.tokenSymbol ?? 'ETH', sub: 'ERC-20 形状 · u256 金额', amount: info ? amt(fmtAmount(info.balanceHuman)) : '—', amountCls: info ? '' : 'dim' }),
      ]),
      cd('最新动态', txs.length === 0 ? [emptyBox(hist?.error ? errorText(hist.error) : '暂无交易记录')] : txs.map(chainTxRow),
        { more: '查看全部', moreAttrs: { 'data-nav': 'history:stk', id: 'stk-news-more' } }),
      net?.faucet ? cd('devnet 水龙头', [
        field('领取金额（ETH）', input('stk-faucet-amount', { type: 'text', value: '10', cls: 'mono' })),
        btn('注册账户 + 领取测试币', { cls: 'btn-s', id: 'stk-faucet-btn', attrs: { 'data-act': 'stk-faucet' } }),
        h('p', { class: 'hint-s', style: 'text-align:left', text: '开发链内置：先 UDC 部署账户合约，再出资。' }),
      ]) : null,
      chainManageCard('stk', st),
    ],
    sheets: recvSheet('ovl-stk-recv', '收款 · Starknet 层', st.address, `${net?.name ?? ''} · ${net?.chainId ?? ''}`),
  };
}

act('stk-faucet', async () => {
  const v = (document.getElementById('stk-faucet-amount')?.value ?? '').trim();
  const res = await send({ type: 'popup:stkFaucet', amountHuman: v || '10' });
  if (res?.error) { toast(errorText(res.error)); return; }
  const r = await send({ type: 'popup:stkRefresh' });
  if (!r?.error) rt.stkInfo = r;
  toast('水龙头已领取');
  render();
});

// ---- 账簿共享构件（链=参数） ----

act('evm-faucet', async () => {
  const scope = currentScr();
  clearErr(scope);
  const v = (document.getElementById('evm-faucet-amount')?.value ?? '').trim();
  const res = await send({ type: 'popup:evmFaucet', amountEth: v || '1' });
  if (res?.error) { setErr(scope, res.error); return; }
  const r = await send({ type: 'popup:evmRefresh' });
  if (!r?.error) rt.evmInfo = r;
  toast('水龙头已领取');
  render();
});

function chainBalanceTot(chain, value, unit, addr, extraKids) {
  return h('div', { class: 'tot' }, [
    h('div', { class: 'tot-l' }, [`总余额 · ${unit}`]),
    h('div', { class: 'tot-a', id: `${chain}-balance` }, [amt(value), h('span', { class: 'u', text: ` ${unit}` })]),
    h('div', { class: 'tot-s' }, [
      h('span', { class: 'mono', id: `${chain}-address`, style: 'font-size:10px;word-break:break-all', text: addr ?? '—' }),
      iconBtn('copy', { bare: true, attrs: { 'data-copy': `#${chain}-address`, title: '复制完整地址' } }),
      iconBtn('qr', { bare: true, attrs: { 'data-open': `ovl-${chain}-recv`, id: `${chain}-recv`, title: '收款' } }),
      iconBtn('refresh', { bare: true, attrs: { 'data-act': `${chain}-refresh`, id: `${chain}-balance-refresh`, title: '刷新' } }),
      ...extraKids,
    ]),
  ]);
}

function chainActs(chain) {
  const acts = [
    h('button', { type: 'button', 'data-nav': `send:${chain}`, id: `${chain}-send` }, [ic('send'), '发送']),
    h('button', { type: 'button', 'data-open': `ovl-${chain}-recv`, id: `${chain}-recv-act` }, [ic('qr'), '收款']),
    h('button', { type: 'button', 'data-nav': `history:${chain}`, id: `${chain}-history` }, [ic('receipt'), '历史']),
    chain === 'stk'
      ? h('button', { type: 'button', 'data-nav': `contract:${chain}`, id: `${chain}-contract` }, [ic('flask'), '合约'])
      : h('button', { type: 'button', 'data-nav': `contract:${chain}`, id: `${chain}-contract` }, [ic('file'), '合约']),
  ];
  return h('div', { class: 'acts' }, acts);
}

function chainTxRow(t) {
  const c = txStatusChip(t.status);
  const dir = txDirection(t, rt.overview?.layers?.[layerKey(rt.chain)]?.address);
  const label = t.kind === 'contract' ? (t.methodLabel ?? '合约调用') : (dir === 'in' ? '接收' : '发送');
  return txRow({
    iconName: t.kind === 'contract' ? 'file' : dir === 'in' ? 'recv' : 'send',
    ticCls: c.text === '成功' ? 'ok' : t.status === 'pending' || t.status === 'received' ? 'warn' : c.cls === 'ch-bad' ? 'bad' : 'blue',
    name: `${label} · ${fmtAmount(t.valueHuman ?? '0')}`,
    sub: `${shortAddr(t.hash, 8, 6)} · ${relTime(t.createdAtMs)}${t.source === 'explorer' ? ' · 链上' : ''}`,
    amount: dir === 'in' ? fmtSigned(t.valueHuman ?? '0', { positive: true }) : fmtSigned(t.valueHuman ?? '0', { negative: true }),
    amountCls: dir === 'in' ? 'pos' : 'neg',
    chipNode: chip(c.text, `ch-xs ${c.cls}`),
  });
}

function chainManageCard(chain, st) {
  return cd('账户管理', [
    lr('私钥 · 口令 · RPC', '危险区需二次确认', { dim: true }),
    btn('进入账户管理', { cls: 'btn-s btn-sm', id: `${chain}-manage`, attrs: { 'data-nav': `manage:${chain}`, style: 'width:100%;margin-top:10px' } }),
  ]);
}

act('evm-refresh', () => ACTS['refresh-evm']());
act('stk-refresh', () => ACTS['refresh-stk']());

// ---------------------------------------------------------------------------
// 07 ZChain 转账 · 贪心选币（钱包侧自发起签名）
// ---------------------------------------------------------------------------

RENDERERS['zc-send'] = async () => {
  const st = await send({ type: 'popup:getState' });
  const p = rt.transfer;
  const avail = st?.unlocked ? await availablePlay() : 0;
  const steps = p ? ladderSteps({ current: p.finality.worstProof, outcome: p.finality.reached ? 'ok' : 'blocked', required: p.finality.requiredProof }) : ladderSteps({});
  mount(scr([
    subHeader('转账', { right: chip('GAME', 'ch-play ch-xs') }),
    body([
      field('金额', amountInput('zc-send-amount', { value: formVal('zc-send-amount'), unit: 'PLAY', tkCls: 'tk-play' }), {
        aux: `可用 ${fmtAmount(avail)} · `,
        auxBtn: { text: 'MAX', attrs: { 'data-act': 'zc-send-max', id: 'zc-send-max' } },
      }),
      field('收款 owner', (() => {
        const inp = input('zc-send-owner', { cls: 'mono', placeholder: 'hex66 压缩公钥（不带 0x）', value: formVal('zc-send-owner'), attrs: { style: 'font-size:11.5px;padding-right:70px' } });
        return h('div', { class: 'iw' }, [inp, h('span', { class: 'in-ic' }, [
          iconBtn('copy', { attrs: { 'data-act': 'zc-send-paste', id: 'zc-send-paste', title: '粘贴' } }),
        ])]);
      })()),
      h('div', { class: 'fiat', text: '测试筹码 · 不计价 · 不可与 REAL 域兑换' }),
      p ? cd(`贪心选币 · 消耗 ${p.inputs.length} 张 note`, [
        ...p.inputs.map((n) => lr(shortAddr(n.commitment ?? '', 6, 4), `${fmtAmount(n.amount)} ${n.proof}`, {
          hash: true, kStyle: 'max-width:96px',
          vKids: [h('span', { text: fmtAmount(n.amount) + ' ' }), chip(n.proof, `ch-xs ${n.proof === 'finalized' || n.proof === 'proven' ? 'ch-felt' : 'ch-amb'}`)],
        })),
        lr('找零 note', p.change === '0' ? '0.00（本次无找零）' : `${fmtAmount(p.change)}（回本账户）`, { dim: p.change === '0' }),
        lr('守恒核对', `Σin ${fmtAmount(p.totalIn)} = Σout ${fmtAmount(p.outputs.reduce((a, o) => a + BigInt(o.amount), 0n).toString())}`),
      ]) : cd('贪心选币', [emptyBox('填入金额与收款 owner 后生成选币预览')]),
      cd(null, [
        lr('网络费', '网关代付', { vKids: [h('span', { text: '网关代付 ' }), chip('免费', 'ch-felt ch-xs')] }),
        lr('回执路径', 'signed → seen → included', { dim: true }),
        lr('凭证门槛', p ? `${p.finality.worstProof} → 要求 ${p.finality.requiredProof}` : '—', { dim: !p?.finality?.reached }),
        // 展示-签名一致性：这条摘要由 wallet-core 生成，确认时后台再算一次并比对；
        // 不一致直接 PreviewMismatch，不签。
        p ? lr('签名摘要', '', { hash: true, kStyle: 'max-width:96px', vKids: [h('span', { class: 'mono', id: 'zc-send-digest', style: 'font-size:10.5px', text: p.digest ? shortAddr(p.digest, 12, 10) : 'wallet-core 未返回' })] }) : null,
      ]),
      p ? cd(null, [rail(steps, {
        capLeft: h('span', {}, [
          '支出 note 短板 ', h('b', { style: `color:var(--${p.finality.reached ? 'felt' : 'bad'})`, text: p.finality.worstProof }),
          p.finality.reached ? ' · 满足 GAME 域要求' : ` · 未达 ${p.finality.requiredProof}`,
        ]),
      })]) : null,
      p?.cannotSubmitReasons?.length ? cd('暂不可提交 · 原因', p.cannotSubmitReasons.map((r) => h('div', { class: 'rsn' }, [ic('x', 'ic ic-s'), h('span', { text: r })]))) : null,
      btn('生成预览', { cls: 'btn-s', id: 'zc-send-preview', attrs: { 'data-act': 'zc-send-preview', style: 'margin-bottom:9px' } }),
      btn('确认转账', { id: 'zc-send-confirm', disabled: !p?.canSubmit, attrs: { 'data-act': 'zc-send-confirm', 'data-enter': '1' } }),
      errLine('zc-send-err'),
      h('p', { class: 'hint-s', style: 'margin-top:10px', text: 'note 全额消费：不足额时自动多输出一条找零回本账户。提交后可在「账簿 → 回执」跟踪状态。' }),
    ]),
  ], { aria: 'ZChain 转账' }));
};

async function availablePlay() {
  const res = await send({ type: 'popup:getNotes' });
  if (res?.error) return '0';
  return groupBalances(res.balances ?? {}).game.play.free.toString();
}

act('zc-send-max', async () => {
  const v = await availablePlay();
  const n = document.getElementById('zc-send-amount');
  if (n) n.value = v;
  rt.transfer = null;
  render();
});

act('zc-send-paste', async () => {
  try {
    const txt = await navigator.clipboard.readText();
    const n = document.getElementById('zc-send-owner');
    if (n) n.value = txt.trim();
    toast('已粘贴');
  } catch {
    toast('剪贴板读取未授权：请手动粘贴');
  }
});

act('zc-send-preview', async () => {
  const scope = currentScr();
  clearErr(scope);
  rt.transfer = null;
  captureForm('zc-send-amount', 'zc-send-owner');
  const res = await send({
    type: 'popup:transferPreview',
    amount: document.getElementById('zc-send-amount').value,
    owner: document.getElementById('zc-send-owner').value.trim(),
  });
  if (res?.error) { setErr(scope, res.error); render(); return; }
  rt.transfer = res.preview;
  render();
});

act('zc-send-confirm', async () => {
  const scope = currentScr();
  clearErr(scope);
  const p = rt.transfer;
  if (!p?.canSubmit) { setErr(scope, null, '预览未就绪或不满足提交条件'); return; }
  const res = await send({ type: 'popup:transferConfirm', operation: p.operation, digest: p.digest ?? '' });
  if (res?.error) {
    setErr(scope, res.error);
    rt.transfer = null; // 摘要失效后强制重新预览（不复用旧选币结果）
    render();
    return;
  }
  rt.transfer = null;
  dropForm('zc-send-amount', 'zc-send-owner');
  toast(`已签名并登记回执 · ${shortAddr(res.digest, 8, 6)}`);
  rt.chain = 'zc';
  rt.screen = 'zc-receipts';
  render();
});

// ---------------------------------------------------------------------------
// 08 REAL 提现预览 · fail-closed（展示态，提交入口恒禁用）
// ---------------------------------------------------------------------------

RENDERERS['zc-withdraw'] = async () => {
  const p = rt.withdraw;
  const avail = await availableReal();
  const steps = p ? ladderSteps({ current: p.finality.worstProof, outcome: p.finality.reached ? 'ok' : 'blocked', required: p.finality.requiredProof }) : ladderSteps({});
  mount(scr([
    subHeader('提现（预览）', { right: chip('REAL', 'ch-real ch-xs') }),
    body([
      banner('real', '托管警示', 'REAL 域由运营方托管映射。以下为模拟预览，不会提交任何链上交易。'),
      field('提现金额', amountInput('wd-amount', { value: formVal('wd-amount'), unit: 'NATIVE', tkCls: 'tk-real' }), { aux: `REAL 可用 ${fmtAmount(avail)}` }),
      field('收款 owner（L1 地址）', input('wd-owner', { cls: 'mono', placeholder: 'hex66 压缩公钥', value: formVal('wd-owner'), attrs: { style: 'font-size:11.5px' } })),
      p ? cd(`贪心选币 · ${p.inputs.length} 张 note`, [
        ...p.inputs.map((n) => lr(shortAddr(n.commitment ?? '', 6, 4), '', {
          hash: true, kStyle: 'max-width:88px',
          vKids: [h('span', { text: fmtAmount(n.amount) + ' ' }), chip(n.proof, `ch-xs ${n.proof === 'finalized' ? 'ch-felt' : n.proof === 'proven' ? 'ch-felt' : 'ch-amb'}`)],
        })),
        lr('合计', fmtAmount(p.inputs.reduce((a, n) => a + BigInt(n.amount || '0'), 0n).toString())),
      ]) : cd('贪心选币', [emptyBox('填入金额与 owner 后生成预览')]),
      cd('finality 检查', [
        rail(steps),
        lr('所需证明', p ? p.finality.requiredProof : 'finalized'),
        lr('最弱凭证', p ? `${p.finality.worstProof}${p.finality.reached ? '' : '（未达标）'}` : '—', { dim: !p?.finality?.reached }),
      ]),
      cd('暂不可提交 · 原因', p
        ? [
          ...p.cannotSubmitReasons.map((r) => h('div', { class: 'rsn' }, [ic('x', 'ic ic-s'), h('span', { text: r })])),
          h('div', { class: 'rsn real' }, [ic('lock', 'ic ic-s'), h('span', { text: `托管：${p.custodyRisk ?? 'real_is_custodial'}` })]),
        ]
        : [emptyBox('尚未生成预览')]),
      btn('生成预览', { cls: 'btn-s', id: 'wd-preview', attrs: { 'data-act': 'wd-preview', style: 'margin-bottom:9px' } }),
      btn('提交提现', { id: 'wd-submit', disabled: true }),
      h('p', { class: 'hint-s', style: 'margin-top:10px', text: 'fail-closed：canSubmit 由 wallet-core 展示门与 finality 合取决定，UI 只消费。虚线笔触即「不可用」的专用表达。' }),
      errLine('wd-err'),
    ]),
  ], { aria: 'REAL 提现预览' }));
};

async function availableReal() {
  const res = await send({ type: 'popup:getNotes' });
  if (res?.error) return '0';
  return groupBalances(res.balances ?? {}).real.native.free.toString();
}

act('wd-preview', async () => {
  const scope = currentScr();
  clearErr(scope);
  rt.withdraw = null;
  captureForm('wd-amount', 'wd-owner');
  const res = await send({
    type: 'popup:withdrawPreview',
    amount: document.getElementById('wd-amount').value,
    owner: document.getElementById('wd-owner').value.trim(),
  });
  if (res?.error) { setErr(scope, res.error); render(); return; }
  rt.withdraw = res.preview;
  render();
});

// ---------------------------------------------------------------------------
// 09 dapp 签名请求（连接 / 换网 / 签名三类共用一屏，逐字段结构化预览）
// ---------------------------------------------------------------------------

RENDERERS['zc-confirm'] = async () => {
  const res = await send({ type: 'popup:listPending' });
  const pending = res?.pending ?? [];
  const reg = await send({ type: 'popup:getRegistry' });
  const nodes = [];
  if (pending.length === 0) {
    nodes.push(emptyBox('无待确认请求'), btn('返回账簿', { cls: 'btn-s', attrs: { 'data-nav': `acct:${rt.chain}`, id: 'confirm-none-back' } }));
  }
  for (const p of pending) nodes.push(...confirmCard(p, reg?.sessionKeys ?? []));
  mount(scr([
    subHeader('签名请求', {
      closeIcon: true,
      right: pending[0] ? chip(remainText((pending[0].expiresAt ?? 0) - Date.now()), 'ch-amb ch-xs mono') : null,
    }),
    body(nodes),
  ], { aria: '签名确认' }));
  const countdown = document.querySelector('.sub-s .ch');
  if (countdown && pending[0]?.expiresAt) {
    countdown.setAttribute('data-countdown', String(pending[0].expiresAt));
    countdown.removeAttribute('text');
    tickCountdowns();
  }
};

function confirmCard(p, sessionKeys) {
  const id = p.requestId;
  const head = h('div', { class: 'dapp' }, [
    h('span', { class: 'dapp-fav' }, [ic('spade', 'ic ic-s')]),
    h('div', { class: 'grow', style: 'min-width:0' }, [
      h('b', { text: p.origin }),
      h('span', { text: p.kind === 'connect' ? '请求连接并读取账户' : p.kind === 'switch_network' ? '请求切换网络' : '请求签名' }),
    ]),
    chip(p.method.replace('zchain_', ''), 'ch-felt ch-xs'),
  ]);
  if (p.kind === 'connect') {
    return [head,
      cd('请求内容', [lr('method', p.method), lr('request_id', shortAddr(id, 10, 6)), lr('过期', remainText((p.expiresAt ?? 0) - Date.now()) + ' 后')]),
      banner('info', '批准即授权', '该站点可读取公钥与 PLAY 余额状态；授权写入当前账户的授权簿，可随时在会话密钥页撤销。'),
      decideRow(id),
    ];
  }
  if (p.kind === 'switch_network') {
    const pv = p.preview ?? {};
    return [head,
      cd('网络切换（二次确认）', [
        lr('当前网络', `${pv.fromChainId}（${pv.fromKind}）`),
        lr('目标网络', `${pv.toChainId}（${pv.toKind}）`),
      ]),
      banner('bad', '换网即改变签名域', 'chain_id 参与签名摘要；devnet/testnet 之外的网络不在注册表内，一律拒绝。'),
      decideRow(id),
    ];
  }
  const pv = p.preview ?? {};
  const ab = assetBadge(pv.asset_class ?? 'PLAY');
  const gov = (sessionKeys ?? []).find((b) => b.origin === p.origin && b.status === 'active');
  const amount = pv.amount_in ?? '0';
  return [
    head,
    h('div', { class: 'cfm' }, [
      h('div', { class: 'l', text: kindLabel(pv.kind) }),
      h('div', { class: 'v neg', text: `-${fmtAmount(amount)}` }),
      h('div', { class: 's', text: `${ab.ok ? ab.tokenLabel : pv.asset_class} · ${(pv.domain ?? 'zchain').toUpperCase()} 域 · ${ab.domainName ?? ''}` }),
    ]),
    cd('请求内容', [
      lr('链', pv.chain_id ?? '—'),
      pv.table_id != null ? lr('桌 table_id', pv.table_id) : null,
      lr('资产', ab.ok ? `${ab.domainName}/${ab.tokenLabel}` : String(pv.asset_class ?? '未知'), { vKids: [h('span', { text: ab.ok ? `${ab.domainName}/${ab.tokenLabel} ` : String(pv.asset_class ?? '未知') }), chip(ab.domainName ?? '—', `ch-xs ${ab.badgeClass ?? ''}`)] }),
      lr('amount_out', fmtAmount(pv.amount_out ?? '0')),
      lr('rake', fmtAmount(pv.rake ?? '0')),
      (pv.proof_states ?? []).length ? lr('proof 层级', (pv.proof_states ?? []).join(' / ')) : null,
      lr('过期', `${Math.max(0, Math.round(((p.expiresAt ?? 0) - Date.now()) / 1000))}s`, { vKids: [h('span', { text: '倒计时 ' }), chip(remainText((p.expiresAt ?? 0) - Date.now()), 'ch-amb ch-xs')] }),
    ]),
    cd('授权对象', [
      ...(pv.outputs ?? []).map((o, i) => lr(`输出#${i} owner`, `${shortAddr(o.owner ?? '', 8, 6)} · ${fmtAmount(o.amount ?? '0')}`)),
      pv.request_id ? lr('request_id', shortAddr(pv.request_id, 8, 6)) : null,
      pv.hand_binding ? lr('hand_binding', shortAddr(pv.hand_binding, 8, 6)) : null,
      lr('nonce', pv.nonce ?? '—'),
      lr('确认摘要', shortAddr(pv.digest ?? '', 10, 8)),
      lr('证明', '结算后可在 Portal 完整验证', { dim: true }),
    ]),
    gov
      ? banner('ok', '将使用会话密钥签名', `在单笔限额（≤ ${gov.perTxLimit ?? '不限'}）与日累计（${sessionUsage(gov).usedText}/${sessionUsage(gov).limitText}）内。`)
      : banner('info', '签名路径：主密钥', '该 origin 无生效中的会话密钥；本次以账户主密钥签名。'),
    banner('bad', '签名前请逐字段核对', '以上展示即签名内容（预览摘要绑定）。任何字段与预期不符请拒绝。'),
    decideRow(id),
    h('details', {}, [
      h('summary', { text: '原始摘要' }),
      h('div', { class: 'raw', text: String(pv.digest ?? '—') }),
    ]),
  ];
}

function decideRow(requestId) {
  return h('div', { class: 'btn-row', style: 'margin-top:2px' }, [
    btn('拒绝', { cls: 'btn-d', id: `reject-${requestId}`, attrs: { 'data-act': 'decide', 'data-id': requestId, 'data-choice': 'reject' } }),
    btn('批准', { cls: 'btn-p', id: `approve-${requestId}`, attrs: { 'data-act': 'decide', 'data-id': requestId, 'data-choice': 'approve' } }),
  ]);
}

act('decide', async (node) => {
  const requestId = node.getAttribute('data-id');
  const type = node.getAttribute('data-choice') === 'approve' ? 'popup:approve' : 'popup:reject';
  const res = await send({ type, requestId });
  if (res?.error) { toast(errorText(res.error)); return; }
  toast(node.getAttribute('data-choice') === 'approve' ? '已批准' : '已拒绝');
  render();
});

// ---------------------------------------------------------------------------
// 10 会话密钥 · SNIP-12（现有会话 / 新建草稿）
// ---------------------------------------------------------------------------

RENDERERS['zc-sessions'] = async () => {
  const reg = await send({ type: 'popup:getRegistry' });
  const keys = reg?.sessionKeys ?? [];
  const origins = reg?.origins ?? [];
  const draft = rt.draft;
  const st = await send({ type: 'popup:getState' });
  mount(scr([
    subHeader('会话密钥', { right: chip('SNIP-12', 'ch-xs mono') }),
    body([
      h('div', { class: 'seg' }, [
        h('button', { class: 'on', type: 'button', 'data-seg': 'list', id: 'seg-list', text: '现有会话' }),
        h('button', { type: 'button', 'data-seg': 'new', id: 'seg-new', text: '新建草稿' }),
        h('button', { type: 'button', 'data-seg': 'origin', id: 'seg-origin', text: `授权簿 ${origins.length}` }),
      ]),
      h('div', { 'data-pane': 'list' }, keys.length === 0 ? [emptyBox('暂无会话密钥授权')] : keys.map(sessionCard)),
      h('div', { 'data-pane': 'new', style: 'display:none' }, [draftForm(draft, st)]),
      h('div', { 'data-pane': 'origin', style: 'display:none' }, [
        origins.length === 0 ? emptyBox('无已授权站点') : cd('origin 授权', origins.map((o) => lr(o.origin, o.grantedAt ? new Date(o.grantedAt).toLocaleString() : '（迁移）', {
          vKids: [h('span', { text: shortAddr(o.origin, 18, 8) }), btn('撤销', { cls: 'btn-o btn-sm', attrs: { 'data-act': 'revoke-origin', 'data-origin': o.origin, style: 'margin-left:8px' } })],
        }))),
        h('p', { class: 'hint-s', style: 'text-align:left;margin-top:8px', text: '撤销后该站点所有请求以 OriginNotPermitted 拒绝（可再次连接重新授权）。' }),
      ]),
      errLine('sessions-err'),
      h('p', { class: 'hint-s', style: 'text-align:left;margin-top:8px', text: '授权簿按 origin 记账；撤销只影响该 origin 的委托密钥，不动主密钥。delegated key 私钥只活在 wasm 会话，锁定即毁。' }),
    ]),
  ], { aria: '会话密钥' }));
};

function sessionCard(b) {
  const c = sessionStatusChip(b.status);
  const u = sessionUsage(b);
  return h('div', { class: 'cd', style: b.status === 'active' ? 'border-color:var(--ink);border-width:1.5px' : 'opacity:.7' }, [
    h('div', { class: 'row', style: 'gap:9px;margin-bottom:9px' }, [
      h('span', { class: `tic ${b.status === 'active' ? 'ok' : 'warn'}`, style: 'width:26px;height:26px' }, [ic('key', 'ic ic-s')]),
      h('div', { class: 'grow', style: 'min-width:0' }, [
        h('div', { class: 'ar-n', style: 'font-size:12.5px', text: b.origin }),
        h('div', { class: 'ar-s', text: `delegated ${shortAddr(b.delegatedPublicKey ?? '', 8, 6)}` }),
      ]),
      chip(c.text, `ch-xs ${c.cls}`),
    ]),
    lr('scope', '', { vKids: (b.allowedScopes ?? []).map((s) => chip(s, 'ch-xs')) }),
    lr('单笔限额', b.perTxLimit ? `≤ ${fmtAmount(b.perTxLimit)}` : '不限'),
    lr('日累计', `${fmtAmount(u.usedText)} / ${fmtAmount(u.limitText)}`),
    u.percent !== null ? meter(u.percent, { warn: u.exhausted, style: 'margin:7px 0' }) : null,
    lr('桌白名单', b.tableAllowlist == null ? '不限桌' : b.tableAllowlist.join(' · ')),
    lr('有效期', validityRemain(b.validUntil)),
    lr('登记来源', b.evidence ?? '—', { dim: true }),
    b.revoked || b.status === 'active' || b.status === 'exhausted'
      ? btn(b.revoked ? '删除记录' : '撤销授权', {
        cls: b.revoked ? 'btn-g btn-sm' : 'btn-d btn-sm',
        id: `session-${b.revoked ? 'del' : 'revoke'}-${shortAddr(b.bindingId, 6, 4)}`,
        attrs: { 'data-act': b.revoked ? 'session-delete' : 'session-revoke', 'data-id': b.bindingId, style: 'margin-top:11px;width:100%' },
      })
      : btn('删除记录', { cls: 'btn-g btn-sm', attrs: { 'data-act': 'session-delete', 'data-id': b.bindingId, style: 'margin-top:11px;width:100%' } }),
    b.revoked ? h('p', { class: 'hint-s', style: 'margin-top:7px', text: '已撤销为粘滞态：该 origin 的签名一律拒绝，删除记录后回到常规路径。' }) : null,
  ]);
}

function draftForm(draft, st) {
  if (draft) {
    return cd('SNIP-12 AuthorizeZChainKey（确认后登记）', [
      lr('origin', draft.origin),
      lr('chain_id', draft.request.chainId),
      lr('account_address', shortAddr(draft.request.accountAddress, 10, 8)),
      lr('delegated_public_key', shortAddr(draft.key.delegated_public_key ?? '', 10, 8)),
      lr('allowed_scopes', '', { vKids: (draft.request.allowedScopes ?? []).map((s) => chip(s, 'ch-xs')) }),
      lr('单笔 / 日限额', `${draft.request.perTxLimit ?? '不限'} / ${draft.request.perDayLimit ?? '不限'}`),
      lr('桌白名单', draft.request.tableAllowlist == null ? '全部桌' : draft.request.tableAllowlist.join(' · ')),
      lr('有效期', `${draft.request.validAfter} → ${draft.request.validUntil}`),
      lr('nonce', draft.request.nonce),
      lr('SNIP-12 摘要', shortAddr(draft.digest, 12, 8)),
      banner('bad', '请逐字段核对摘要', '登记即把约束写入授权簿（devnet 入口形态：本地登记，链侧 admission 登记未接——evidence 如实标注）。'),
      h('div', { class: 'btn-row' }, [
        btn('取消', { cls: 'btn-g', id: 'draft-cancel', attrs: { 'data-act': 'draft-cancel' } }),
        btn('确认登记', { id: 'draft-register', attrs: { 'data-act': 'draft-register' } }),
      ]),
      h('details', {}, [h('summary', { text: 'typed data（encode_type）' }), h('div', { class: 'raw', text: JSON.stringify(draft.typedData ?? {}) })]),
    ]);
  }
  return [
    cd('授权面向', [
      field('origin', input('draft-origin', { cls: 'mono', placeholder: 'http://localhost:8080', attrs: { style: 'font-size:11.5px' } })),
      field('授权方账户地址（felt hex）', input('draft-addr', { cls: 'mono', placeholder: st?.publicKey ? `当前公钥 ${shortAddr(st.publicKey, 8, 6)}` : '0x…', value: '', attrs: { style: 'font-size:11.5px' } })),
    ]),
    cd('scope 授权', [
      chk('开桌 / 对局（play）', { on: true, gate: 'scope' }),
      chk('买入（buyin）', { on: true, gate: 'scope' }),
      chk('下注（bet）', { on: true, gate: 'scope' }),
      chk('结算（settle）', { on: true, gate: 'scope' }),
      chk('转账（transfer）', { gate: 'scope' }),
      h('p', { class: 'hint-s', style: 'text-align:left;margin-top:6px', text: 'withdraw 永不可选：提现签名面未开放。scope 全部取消勾选时，登记入口自动禁用。' }),
    ]),
    field('单笔限额', input('draft-per-tx', { cls: 'mono', value: '1000', attrs: { style: 'font-size:15px' } })),
    field('日累计限额', input('draft-per-day', { cls: 'mono', value: '5000', attrs: { style: 'font-size:15px' } })),
    field('桌白名单', input('draft-tables', { cls: 'mono', placeholder: 'table_id，逗号分隔（留空 = 不限桌，不推荐）', attrs: { style: 'font-size:11.5px' } })),
    field('有效期（小时）', input('draft-hours', { cls: 'mono', value: '168', attrs: { style: 'font-size:15px' } })),
    btn('生成摘要并确认', { id: 'draft-generate', disabled: true, attrs: { 'data-gated': 'scope', 'data-act': 'draft-generate' } }),
    h('p', { class: 'hint-s', style: 'text-align:left;margin-top:10px', text: 'delegated key 由 wallet-core 生成；摘要由 wallet-core poseidon 计算，UI 不算第二份。' }),
  ];
}

act('draft-generate', async () => {
  const scope = currentScr();
  clearErr(scope);
  const checked = [...scope.querySelectorAll('[data-check="[data-gated=scope]"]')]
    .filter((n) => n.querySelector('.cb.on'))
    .map((n) => ({ play: 'play', buyin: 'buyin', bet: 'bet', settle: 'settle', transfer: 'transfer' }[n.textContent.trim().match(/（([a-z]+)）/)?.[1]] ?? null))
    .filter(Boolean);
  const res = await send({
    type: 'popup:sessionDraft',
    origin: document.getElementById('draft-origin').value.trim(),
    accountAddress: document.getElementById('draft-addr').value.trim(),
    allowedScopes: checked,
    perTxLimit: document.getElementById('draft-per-tx').value.trim() || null,
    perDayLimit: document.getElementById('draft-per-day').value.trim() || null,
    tableAllowlist: document.getElementById('draft-tables').value,
    validitySec: Number(document.getElementById('draft-hours').value.trim() || 168) * 3600,
  });
  if (res?.error) { setErr(scope, res.error); return; }
  rt.draft = res;
  render();
});

act('draft-cancel', () => { rt.draft = null; render(); });

act('draft-register', async () => {
  const scope = currentScr();
  const d = rt.draft;
  clearErr(scope);
  if (!d) return;
  const res = await send({
    type: 'popup:sessionRegister',
    origin: d.origin,
    binding: {
      bindingId: d.key.binding_id,
      delegatedPublicKey: d.key.delegated_public_key,
      chainId: d.request.chainId,
      accountAddress: d.request.accountAddress,
      allowedScopes: d.request.allowedScopes,
      perTxLimit: d.request.perTxLimit,
      perDayLimit: d.request.perDayLimit,
      tableAllowlist: d.request.tableAllowlist,
      nonce: d.request.nonce,
      validAfter: d.request.validAfter,
      validUntil: d.request.validUntil,
      digest: d.digest,
    },
  });
  if (res?.error) { setErr(scope, res.error); return; }
  rt.draft = null;
  toast('已登记（evidence 标注 devnet_local_entry）');
  render();
});

act('session-revoke', async (node) => {
  const res = await send({ type: 'popup:sessionRevoke', bindingId: node.getAttribute('data-id') });
  if (res?.error) { toast(errorText(res.error)); return; }
  toast('撤销为粘滞操作：该 origin 的签名一律拒绝');
  render();
});

act('session-delete', async (node) => {
  const res = await send({ type: 'popup:sessionDelete', bindingId: node.getAttribute('data-id') });
  if (res?.error) { toast(errorText(res.error)); return; }
  toast('记录已删除');
  render();
});

act('revoke-origin', async (node) => {
  const res = await send({ type: 'popup:revokeOrigin', origin: node.getAttribute('data-origin') });
  if (res?.error) { toast(errorText(res.error)); return; }
  toast('已撤销该站点授权');
  render();
});

// ---------------------------------------------------------------------------
// 11 Proof Portal（弹窗内四步验证；stw○ wasm 耗时如实展示）
// ---------------------------------------------------------------------------

const PORTAL_STEPS = [
  { title: '拉取结算明细', hint: '网关 settlement 端点' },
  { title: '下载 STARK 证明', hint: 'proof 归档 payload' },
  { title: '浏览器内完整验证', hint: 'stwo wasm：FRI + Merkle + 约束 + scope 重建' },
  { title: 'wallet-core 本地复验', hint: '结算关系与 payout_root 比对' },
];

RENDERERS['zc-portal'] = async () => {
  const st = await send({ type: 'popup:getState' });
  const p = rt.portal;
  const running = p?.running === true;
  mount(scr([
    subHeader('Proof Portal', { right: chip('STARK', 'ch-felt ch-xs') }),
    body([
      field('hand binding', input('portal-binding', {
        cls: 'mono', value: p?.binding ?? '', placeholder: '64 位 hex（不带 0x）',
        attrs: { style: 'font-size:11.5px', disabled: running ? '' : null },
      }), { aux: `网关 ${st?.gatewayUrl ?? '未配置'}` }),
      btn(running ? '验证中…' : '验证这一手牌', { id: 'portal-verify', icon: 'shield', attrs: { 'data-act': 'portal-verify', disabled: running ? '' : null } }),
      p ? cd('验证步骤', [h('div', { class: 'steps' }, p.steps.map((s, i) => h('div', { class: `stp ${s.state}`, id: `portal-step-${i}` }, [
        h('i', {}, [s.state === 'done' ? ic('check', 'ic ic-xs') : s.state === 'run' ? ic('refresh', 'ic ic-xs') : s.state === 'bad' ? ic('x', 'ic ic-xs') : String(i + 1)]),
        h('div', {}, [h('b', { text: s.title }), h('span', { text: s.sub ?? '' })]),
      ])))], { more: `${p.steps.filter((s) => s.state === 'done').length}/${PORTAL_STEPS.length}`, moreAttrs: {} }) : null,
      p?.settlement ? cd('结算摘要', [
        lr('hand_binding', shortAddr(p.settlement.hand_binding ?? '', 10, 8)),
        lr('table_id', p.settlement.table_id ?? '—'),
        lr('底池', `${fmtAmount(p.settlement.pot ?? '0')}`),
        lr('rake', `${fmtAmount(p.settlement.rake?.total ?? '0')}（层级 ${p.settlement.level ?? '—'}）`),
        lr('payout_root', shortAddr(p.settlement.payout_root ?? '', 10, 8)),
        lr('inputs / payouts', `${(p.settlement.inputs ?? []).length} / ${(p.settlement.payouts ?? []).length}`),
        h('p', { class: 'hint-s', style: 'text-align:left;margin-top:6px', text: '层级是网关水位声明：原样展示、不推进。' }),
      ]) : null,
      p?.proof !== undefined ? cd('证明产物', p.proof ? [
        lr('engine', p.proof.engine ?? '未知'),
        lr('engine 来源', p.proof.engineSource ?? '—'),
        lr('payload 字节数', fmtAmount(p.proof.payloadLen ?? '—')),
      ] : [emptyBox('该结算无已归档证明产物（网关 404）——STARK 阶段如实跳过')]) : null,
      p?.stark ? cd('STARK 完整验证', [
        lr('结论', p.stark.ok ? 'verified' : (p.stark.skipped ? 'skipped' : 'rejected')),
        lr('耗时', `${(p.stark.elapsedMs ?? 0).toFixed(0)} ms`),
        ...(p.stark.stats ? Object.entries(p.stark.stats).slice(0, 5).map(([k, v]) => lr(k, String(v))) : []),
        p.stark.ok ? null : h('p', { class: 'hint-s', style: 'text-align:left;margin-top:6px', text: p.stark.reason ?? '' }),
      ]) : null,
      p?.verdict ? cd('wallet-core 复验', [
        lr('结论', p.verdict.verdict === 'verified' ? 'verified（结算关系复验一致）' : 'rejected（复验不一致）'),
        ...verdictList(p.verdict),
        lr('耗时', `${(p.verdictElapsedMs ?? 0).toFixed(0)} ms`),
      ]) : null,
      p && p.conclusion ? h('div', { style: 'display:flex;justify-content:center;margin:4px 0 12px' }, [
        seal(p.conclusion === 'verified' ? '已验证' : p.conclusion === 'partial' ? '部分验证' : '未通过',
          p.conclusion === 'verified' ? 'seal-ok' : 'seal-bad'),
      ]) : null,
      p?.error ? banner('bad', p.error.code ?? '验证失败', p.error.reason ?? '') : null,
      p && p.conclusion ? banner(
        p.conclusion === 'verified' ? 'ok' : 'bad',
        p.conclusion === 'verified' ? '验证通过' : `未达「已验证」：${p.conclusion === 'partial' ? '存在跳过/失败的阶段' : '结论不成立'}`,
        '两项验证相互独立：任一阶段被跳过或拒绝，整体结论就不是 fully verified（fail-closed，不合并成"看起来通过"）。',
      ) : null,
      banner('info', '性能如实标注', '浏览器内完整验证约 1.7–2.0s，超出 500ms 交互预算：进度逐步展示，不伪装即时完成。'),
      banner('info', '验证在本地完成', '证明文件与结算明细由网关拉取，复验在 wallet-core / stwo wasm 本地执行；不依赖服务端「已验证」结论。'),
      mi({ iconName: 'ext', title: '在独立页打开完整 Portal', sub: 'portal/portal.html · 支持权限授予与逐阶段明细', attrs: { 'data-act': 'portal-open' } }),
      errLine('portal-err'),
    ]),
  ], { aria: 'Proof Portal' }));
};

function verdictList(verdict) {
  const verifier = verdict?.verifier ?? {};
  const rows = [lr('verifier', `${verifier.name ?? '?'} v${verifier.version ?? '?'}（ABI v${verifier.abi_version ?? '?'}）`)];
  for (const r of verdictRows(verdict)) {
    rows.push(lr(r.label, '', {
      vKids: [h('span', { text: `${r.detail ? `${r.detail} ` : ''}` }), chip(r.ok ? '✓' : '✗', `ch-xs ${r.ok ? 'ch-felt' : 'ch-bad'}`)],
    }));
  }
  return rows;
}

act('portal-open', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('portal/portal.html') });
});

act('portal-verify', async () => {
  const binding = document.getElementById('portal-binding').value.trim();
  const st = await send({ type: 'popup:getState' });
  const gateway = st?.gatewayUrl;
  const steps = PORTAL_STEPS.map((s) => ({ ...s, state: '', sub: s.hint }));
  rt.portal = { binding, steps, running: true, settlement: null, proof: undefined, stark: null, verdict: null, conclusion: null, error: null };
  render();
  const bump = (patch) => {
    Object.assign(rt.portal, patch, { running: true });
    render();
  };
  try {
    if (!gateway) throw { code: 'GatewayNotConfigured', reason: '当前网络未配置网关' };
    const b = parseBinding(binding);
    if (!b.ok) throw { code: b.code, reason: b.reason };
    steps[0].state = 'run';
    bump({});
    const s = await fetchSettlement(gateway, b.binding);
    if (!s.ok) throw { code: s.code, reason: s.reason };
    steps[0].state = 'done';
    steps[0].sub = `网关 ${new URL(gateway).host} · 水位 ${s.detail?.level ?? '—'}`;
    bump({ settlement: s.detail });

    steps[1].state = 'run';
    bump({});
    let proof = null;
    const pf = await fetchProof(gateway, b.binding);
    if (pf.ok) proof = pf.proof;
    else if (pf.code !== 'ProofNotFound') throw { code: pf.code, reason: pf.reason };
    steps[1].state = 'done';
    steps[1].sub = proof ? `payload ${((proof.payloadLen ?? 0) / 1024).toFixed(1)} KB · engine ${proof.engine ?? '未知'}` : '无归档证明（如实跳过）';
    bump({ proof });

    steps[2].state = 'run';
    bump({});
    // verifyStarkProof 的成功形状是 {ok, stark:{...elapsedMs}}——统一摊平给 UI，
    // UI 只看 {ok, skipped?, code?, reason?, stats?, elapsedMs}。
    const raw = proof?.payloadB64
      ? await verifyStarkProof(proof.payloadB64, verifyCanonicalArchive)
      : { ok: false, skipped: true, code: 'ProofNotFound', reason: '无归档证明，STARK 阶段跳过' };
    const stark = {
      ok: raw.ok === true,
      skipped: raw.skipped === true,
      code: raw.code,
      reason: raw.reason,
      stats: raw.stark?.stats ?? raw.stats ?? null,
      elapsedMs: raw.stark?.elapsedMs ?? raw.elapsedMs ?? 0,
    };
    steps[2].state = stark.ok ? 'done' : 'bad';
    steps[2].sub = stark.ok ? `verified · ${stark.elapsedMs.toFixed(0)} ms` : `${stark.code ?? 'Rejected'} · 如实标注`;
    bump({ stark });

    steps[3].state = 'run';
    bump({});
    // 复验语义全在 wasm：callCore 失败抛 WalletCoreError{code, detail}，
    // verifyLocally 归一为 {ok:false, code, reason}——不二次包装。
    const v = await verifyLocally(s.detail, (json) => callCore('wallet_verify_settlement_detail', json));
    if (!v.ok) throw { code: v.code, reason: v.reason, stark, v };
    steps[3].state = 'done';
    steps[3].sub = `复验 ${String(v.verdict?.verdict ?? '—')} · ${v.elapsedMs.toFixed(0)} ms`;
    // fail-closed 合取：STARK 跳过/被拒 ≠ verified；两项独立。
    const conclusion = stark.ok && v.verdict?.verdict === 'verified'
      ? 'verified'
      : v.verdict?.verdict === 'verified' ? 'partial' : 'failed';
    Object.assign(rt.portal, { steps, verdict: v.verdict, verdictElapsedMs: v.elapsedMs, conclusion, running: false });
    render();
    await appendProofLog({ binding: b.binding, conclusion, elapsedMs: v.elapsedMs, starkElapsedMs: stark.elapsedMs, atMs: Date.now() });
  } catch (e) {
    const cur = steps.find((s) => s.state === 'run');
    if (cur) { cur.state = 'bad'; cur.sub = `${e.code ?? 'Error'}：${e.reason ?? ''}`; }
    if (e.stark) rt.portal.stark = e.stark;
    if (e.v?.verdict) { rt.portal.verdict = e.v.verdict; rt.portal.verdictElapsedMs = e.v.elapsedMs; }
    Object.assign(rt.portal, { running: false, conclusion: 'failed', error: { code: e.code ?? 'Error', reason: e.reason ?? String(e) } });
    render();
    await appendProofLog({ binding: rt.portal.binding, conclusion: 'failed', elapsedMs: 0, atMs: Date.now() });
  }
});

/** 复验记录写成本机凭证簿（最多 20 条；只存结论与耗时，不存 payload）。 */
async function appendProofLog(entry) {
  try {
    const log = await readProofLog();
    log.unshift(entry);
    await chrome.storage.local.set({ [PROOF_LOG_KEY]: log.slice(0, 20) });
  } catch { /* 存储不可用：不掩盖结果，也不阻断验证展示 */ }
}

// ---------------------------------------------------------------------------
// 12 回执状态机（signed → seen → included；ForceInclude 只展示不提交）
// ---------------------------------------------------------------------------

RENDERERS['zc-receipts'] = async () => {
  const res = await send({ type: 'popup:receipts' });
  const all = res?.receipts ?? [];
  const buckets = receiptBuckets(all);
  const pane = (list) => (list.length === 0
    ? [emptyBox('该分桶暂无回执')]
    : [cd(null, list.map(receiptRow), { cls: 'rows' })]);
  mount(scr([
    subHeader('交易回执', { right: chip('signed→seen→included', 'ch-xs mono') }),
    body([
      h('div', { class: 'seg' }, [
        h('button', { class: 'on', type: 'button', 'data-seg': 'all', id: 'rc-seg-all', text: `全部 ${buckets.all.length}` }),
        h('button', { type: 'button', 'data-seg': 'pend', id: 'rc-seg-pend', text: `未上链 ${buckets.pend.length}` }),
        h('button', { type: 'button', 'data-seg': 'done', id: 'rc-seg-done', text: `已上链 ${buckets.done.length}` }),
      ]),
      h('div', { 'data-pane': 'all' }, pane(buckets.all)),
      h('div', { 'data-pane': 'pend', style: 'display:none' }, pane(buckets.pend)),
      h('div', { 'data-pane': 'done', style: 'display:none' }, pane(buckets.done)),
      h('p', {
        class: 'hint-s', style: 'text-align:left;margin-top:2px',
        text: '投递状态 signed → seen → included 单向推进，与凭证阶梯 pending → proven → finalized 是两套独立状态。超 deadline 存在 ForceInclude 协议路径，但当前版本只展示状态、不实现提交（按钮保持禁用）。',
      }),
    ]),
  ], { aria: '交易回执' }));
};

function receiptRow(r) {
  const c = receiptChip(r);
  return h('div', {}, [
    txRow({
      iconName: r.status === 'included' ? 'check' : r.status === 'seen' ? 'receipt' : r.view?.pastDeadline ? 'warn' : 'clock',
      ticCls: r.status === 'included' ? 'ok' : r.status === 'seen' ? 'blue' : r.view?.pastDeadline ? 'bad' : 'warn',
      name: `${kindLabel(r.kind)} · ${shortAddr(r.digest, 10, 8)}`,
      sub: `${r.chainId ?? '—'} · ${relTime(r.signedAtMs)}${r.view?.pastDeadline ? ' · 超出 deadline' : ''}`,
      chipNode: chip(c.text, `ch-xs ${c.cls}`),
    }),
    r.view?.hint ? h('div', { class: 'errx', style: 'color:var(--amb);margin:0 0 6px', text: r.view.hint }) : null,
    r.view?.pastDeadline ? btn('ForceInclude 未开放', { cls: 'btn-g btn-sm', disabled: true, attrs: { title: '本版本仅展示协议状态，提交路径未实现', style: 'margin:2px 0 8px' } }) : null,
    h('details', {}, [
      h('summary', { text: '导入 SeenReceipt / 登记 included' }),
      input(`seen-${shortAddr(r.digest, 6, 4)}`, { placeholder: 'SeenReceipt JSON（chain_id/tx_hash/seen_at_ms/validator_pubkey/signature）', cls: 'mono', attrs: { style: 'font-size:10.5px;margin:7px 0' } }),
      errLine(`rc-err-${shortAddr(r.digest, 6, 4)}`),
      btn('标记 seen（回执未验签，如实标注）', { cls: 'btn-s btn-sm', attrs: { 'data-act': 'receipt-seen', 'data-id': r.digest, style: 'width:100%;margin-bottom:6px' } }),
      btn('人工登记 included（非链上证实）', { cls: 'btn-g btn-sm', attrs: { 'data-act': 'receipt-included', 'data-id': r.digest, style: 'width:100%' } }),
    ]),
  ]);
}

act('receipt-seen', async (node) => {
  const digest = node.getAttribute('data-id');
  const scope = node.closest('.scr');
  const inp = node.closest('details').querySelector('input');
  const err = document.getElementById(`rc-err-${shortAddr(digest, 6, 4)}`);
  if (err) err.textContent = '';
  let receipt = null;
  try { receipt = JSON.parse(inp.value); } catch { if (err) err.textContent = 'JSON 解析失败'; return; }
  const res = await send({ type: 'popup:receiptSeen', digest, receipt });
  if (res?.error) { if (err) err.textContent = errorText(res.error); return; }
  toast('已登记 seen（evidence：receipt_unverified_signature）');
  render();
});

act('receipt-included', async (node) => {
  const res = await send({ type: 'popup:receiptIncluded', digest: node.getAttribute('data-id') });
  if (res?.error) { toast(errorText(res.error)); return; }
  toast('已人工登记 included（evidence：local_manual_entry）');
  render();
});

// ---------------------------------------------------------------------------
// 13-16 链层共享子屏：发送 / 合约 / 记录 / 管理（evm 与 stk 同一套结构）
// ---------------------------------------------------------------------------

/** 每层的 RPC 与字段差异集中在这一张表里（模板不复制两份）。 */
const CHAIN_API = {
  evm: {
    getState: 'popup:evmGetState', create: 'popup:evmCreate', importKey: 'popup:evmImportKey',
    unlock: 'popup:evmUnlock', lock: 'popup:evmLock', refresh: 'popup:evmRefresh',
    prepareTx: 'popup:evmPrepareTx', confirmTx: 'popup:evmConfirmTx', rejectTx: 'popup:evmRejectTx',
    prepareContract: 'popup:evmPrepareContractTx', read: 'popup:evmReadContract', history: 'popup:evmHistory',
    exportKey: 'popup:evmExportKey', changePw: 'popup:evmChangePassword', remove: 'popup:evmRemoveAccount',
    setRpc: 'popup:evmSetRpc', setExplorer: 'popup:evmSetExplorer', faucet: 'popup:evmFaucet',
    unit: 'ETH', chainKey: 'chainIdHex',
  },
  stk: {
    getState: 'popup:stkGetState', create: 'popup:stkCreate', importKey: 'popup:stkImportKey',
    unlock: 'popup:stkUnlock', lock: 'popup:stkLock', refresh: 'popup:stkRefresh',
    prepareTx: 'popup:stkPrepareTx', confirmTx: 'popup:stkConfirmTx', rejectTx: 'popup:stkRejectTx',
    prepareContract: 'popup:stkPrepareTx', read: 'popup:stkReadContract', history: 'popup:stkHistory',
    exportKey: 'popup:stkExportKey', changePw: 'popup:stkChangePassword', remove: 'popup:stkRemoveAccount',
    setRpc: 'popup:stkSetRpc', setExplorer: 'popup:stkSetExplorer', faucet: 'popup:stkFaucet',
    unit: 'ETH', chainKey: 'chainId',
  },
};

function chainName(chain) {
  return CHAIN_LABEL[chain] ?? chain;
}

/** 未创建 / 已锁定层的三个入口（解锁 / 创建 / 导入）。 */
function chainAccessSeg(chain, st) {
  const has = st.hasWallet;
  return [
    h('div', { class: 'seg' }, [
      h('button', { class: has ? 'on' : '', type: 'button', 'data-seg': 'unlock', id: `${chain}-seg-unlock`, text: '解锁本层' }),
      h('button', { class: has ? '' : 'on', type: 'button', 'data-seg': 'create', id: `${chain}-seg-create`, text: '创建本层' }),
      h('button', { type: 'button', 'data-seg': 'import', id: `${chain}-seg-import`, text: '导入私钥' }),
    ]),
    h('div', { 'data-pane': 'unlock', style: has ? '' : 'display:none' }, [
      field('解锁口令', input(`${chain}-unlock-pw`, { type: 'password', placeholder: '本层 keystore 口令' })),
      btn('解锁', { id: `${chain}-unlock-btn`, attrs: { 'data-act': `${chain}-unlock`, 'data-enter': '1' } }),
    ]),
    h('div', { 'data-pane': 'create', style: has ? 'display:none' : '' }, [
      field('账户标签', input(`${chain}-label`, { placeholder: `${chainName(chain)} 主账户` })),
      field('口令', input(`${chain}-pw`, { type: 'password', placeholder: '≥ 8 位' })),
      field('重复口令', input(`${chain}-pw2`, { type: 'password', placeholder: '再次输入' })),
      btn('创建钱包', { id: `${chain}-create-btn`, attrs: { 'data-act': `${chain}-create` } }),
      h('p', { class: 'hint-s', style: 'text-align:left;margin-top:8px', text: '随机私钥 + 口令派生（PBKDF2-SHA256 60 万次）+ AES-256-GCM 存本地；口令丢失无法恢复。' }),
    ]),
    h('div', { 'data-pane': 'import', style: 'display:none' }, [
      field('私钥（hex）', input(`${chain}-import-key`, { cls: 'mono', placeholder: '0x… 或裸 hex', attrs: { style: 'font-size:11.5px' } })),
      field('加密口令', input(`${chain}-import-pw`, { type: 'password', placeholder: '≥ 8 位' })),
      btn('导入为新账户', { cls: 'btn-s', id: `${chain}-import-btn`, attrs: { 'data-act': `${chain}-import` } }),
    ]),
  ];
}

/** 账簿里"本层已锁定/未创建"的数据面占位（方向 B：链=筛选器，缺数据就明说）。 */
function chainAccessPane(chain, st, net) {
  return {
    netText: `${net?.name ?? chainName(chain)} · ${net?.[CHAIN_API[chain].chainKey] ?? ''}`,
    nodes: [
      st.hasWallet
        ? banner('amb', '本层已锁定', '解锁后才能发起签名与查询；地址与账户列表为公开元数据。')
        : banner('info', '本层尚未创建', `三层可分别创建，也可在欢迎页一键创建三层。${chain === 'stk' ? ' Starknet 账户地址由 UDC 公式推导。' : ''}`),
      cd('账户', (st.accounts ?? []).map((a) => assetRow({
        tk: (a.label ?? 'A').slice(0, 1).toUpperCase(),
        name: a.label ?? '未命名',
        sub: shortAddr(a.address ?? '', 12, 8),
        amount: a.active ? '当前' : '切换',
        amountCls: 'dim',
      }))),
      ...chainAccessSeg(chain, st),
      errLine(`${chain}-err`),
    ],
    sheets: null,
  };
}

RENDERERS.send = async () => {
  const chain = rt.chain === 'zc' ? 'evm' : rt.chain;
  const api = CHAIN_API[chain];
  const st = await send({ type: api.getState });
  if (st?.error) { mount(chainErrorScr(chain, st.error)); return; }
  if (!st.unlocked) { go({ id: 'acct', chain }); return; }
  const info = chain === 'evm' ? rt.evmInfo : rt.stkInfo;
  // 草稿按 kind 隔离：合约屏 prepare 出的 write 预览不会串到发送屏被确认。
  const pv = rt.gate?.chain === chain && rt.gate.kind === 'send' ? rt.gate.preview : null;
  mount(scr([
    subHeader('发送', { right: chip(st.networkId ?? chain, 'ch-xs') }),
    body([
      chain === 'evm' ? field('金额', amountInput('evm-tx-value', { value: formVal('evm-tx-value'), unit: 'ETH', tkCls: '' }), {
        aux: info ? `可用 ${fmtAmount(info.balanceHuman)} · ` : '未查询余额',
        auxBtn: info ? { text: 'MAX', attrs: { 'data-act': 'evm-max', id: 'evm-tx-max' } } : null,
      }) : field('金额', amountInput('stk-tx-amount', { value: formVal('stk-tx-amount'), unit: rt.stkInfo?.tokenSymbol ?? 'ETH', tkCls: '' }), {
        aux: info ? `可用 ${fmtAmount(info.balanceHuman)} · ` : '未查询余额',
      }),
      chain === 'evm'
        ? field('收款地址', input('evm-tx-to', { cls: 'mono', placeholder: '0x…', value: formVal('evm-tx-to'), attrs: { style: 'font-size:11.5px' } }))
        : field('收款地址', input('stk-tx-recipient', { cls: 'mono', placeholder: '0x… (felt)', value: formVal('stk-tx-recipient'), attrs: { style: 'font-size:11.5px' } })),
      chain === 'evm' ? h('details', {}, [
        h('summary', { text: 'data（hex，可选：填了即按合约调用签名）' }),
        input('evm-tx-data', { cls: 'mono', placeholder: '0x…', value: formVal('evm-tx-data'), attrs: { style: 'font-size:11px;margin-top:7px' } }),
      ]) : null,
      pv ? chainTxPreview(chain, pv) : cd('交易预览', [emptyBox('填入地址与金额后生成预览')]),
      chain === 'evm'
        ? btn('生成交易预览', { id: 'evm-tx-prepare', attrs: { 'data-act': 'evm-prepare', 'data-enter': '1' } })
        : btn('生成 invoke 预览', { id: 'stk-tx-prepare', attrs: { 'data-act': 'stk-prepare', 'data-enter': '1' } }),
      errLine('send-err'),
      pv ? null : banner('bad', '发送后不可撤销', '请核对地址与金额；chainId 与网络预设不符时交易将被拒绝签名。'),
    ]),
  ], { aria: '发送' }));
};

function chainTxPreview(chain, p) {
  const kids = [
    lr('from', shortAddr(p.from ?? '', 10, 8)),
    lr('to', shortAddr(p.to ?? '', 10, 8)),
    p.methodLabel ? lr('方法', p.methodLabel) : null,
    ...(p.decodedArgs ?? []).map((a) => lr(`arg.${a.name} (${a.type})`, a.value)),
    chain === 'evm' ? lr('value', `${fmtAmount(p.valueHuman)} ETH（${p.valueWei} wei）`) : lr('calldata', (p.calldata ?? []).join(', ')),
    chain === 'evm' ? lr('gas limit', fmtAmount(p.gasLimit)) : lr('selector', shortAddr(p.selector ?? '', 10, 8)),
    chain === 'evm' ? lr('gas price', `${fmtAmount(p.gasPriceGwei)} gwei`) : lr('nonce', p.nonce),
    chain === 'evm' ? lr('nonce', p.nonce) : lr('max fee', `${fmtAmount(p.maxFeeHuman)}（${p.maxFeeWei} wei）`),
    chain === 'evm' ? lr('最大手续费', `${fmtAmount(p.maxFeeHuman)} ETH`) : null,
    lr('chainId', chain === 'evm' ? p.chainIdHex : p.chainId),
    p.data && p.data !== '0x' ? lr('data', `${p.data.slice(0, 42)}…`) : null,
  ];
  return h('div', { id: `${chain}-tx-preview` }, [
    h('div', { class: 'cfm' }, [
      h('div', { class: 'l', text: chain === 'evm' ? (p.kind === 'contract' ? '合约调用' : '转账') : 'invoke v1' }),
      h('div', { class: 'v neg', text: `-${fmtAmount(p.valueHuman ?? '0')}` }),
      h('div', { class: 's', text: chain === 'evm' ? 'ETH · EIP-155 签名后广播' : 'STARK curve ECDSA 签名后广播' }),
    ]),
    cd('交易预览', kids),
    h('div', { class: 'btn-row' }, [
      btn('取消', { cls: 'btn-g', id: `${chain}-tx-reject`, attrs: { 'data-act': `${chain}-tx-reject` } }),
      btn('确认签名并发送', { id: `${chain}-tx-confirm`, attrs: { 'data-act': `${chain}-tx-confirm` } }),
    ]),
  ]);
}

act('evm-max', () => {
  const n = document.getElementById('evm-tx-value');
  if (n && rt.evmInfo) n.value = String(rt.evmInfo.balanceHuman);
  toast('已填入最大可用（gas 需手动预留）');
});

function chainPrepareAct(chain) {
  return async () => {
    const scope = currentScr();
    clearErr(scope);
    rt.gate = null;
    captureForm('evm-tx-to', 'evm-tx-value', 'evm-tx-data', 'stk-tx-recipient', 'stk-tx-amount');
    const res = chain === 'evm'
      ? await send({
        type: CHAIN_API.evm.prepareTx,
        to: document.getElementById('evm-tx-to').value.trim(),
        valueEth: document.getElementById('evm-tx-value').value.trim(),
        dataHex: (document.getElementById('evm-tx-data')?.value ?? '').trim(),
      })
      : await send({
        type: CHAIN_API.stk.prepareTx, preset: 'erc20', method: 'transfer',
        recipient: document.getElementById('stk-tx-recipient').value.trim(),
        amountHuman: document.getElementById('stk-tx-amount').value.trim(),
      });
    if (res?.error) { setErr(scope, res.error); return; }
    rt.gate = { chain, kind: 'send', preview: res.preview };
    render();
  };
}

act('evm-prepare', chainPrepareAct('evm'));
act('stk-prepare', chainPrepareAct('stk'));

act('evm-tx-confirm', () => chainTxConfirm('evm'));
act('stk-tx-confirm', () => chainTxConfirm('stk'));
act('evm-tx-reject', () => chainTxReject('evm'));
act('stk-tx-reject', () => chainTxReject('stk'));

async function chainTxConfirm(chain) {
  const scope = currentScr();
  clearErr(scope);
  const res = await send({ type: CHAIN_API[chain].confirmTx });
  if (res?.error) { setErr(scope, res.error); rt.gate = null; return; }
  // e2e 观测点：广播哈希在重渲染后仍可断言（两条链各一个键，语义不混用）。
  if (chain === 'evm') window.__lastEvmBroadcast = res.hash;
  else window.__lastStkBroadcast = res.hash;
  rt.gate = null;
  dropForm('evm-tx-to', 'evm-tx-value', 'evm-tx-data', 'stk-tx-recipient', 'stk-tx-amount');
  toast(`已广播 · ${shortAddr(res.hash, 10, 8)}`);
  rt.history = null;
  render();
}

async function chainTxReject(chain) {
  await send({ type: CHAIN_API[chain].rejectTx });
  rt.gate = null;
  render();
}

RENDERERS.contract = async () => {
  const chain = rt.chain === 'zc' ? 'evm' : rt.chain;
  const api = CHAIN_API[chain];
  const st = await send({ type: api.getState });
  if (st?.error) { mount(chainErrorScr(chain, st.error)); return; }
  if (!st.unlocked) { go({ id: 'acct', chain }); return; }
  const out = rt.gate?.chain === chain && rt.gate.kind === 'read' ? rt.gate.result : null;
  mount(scr([
    subHeader('合约', { right: chip(chain === 'evm' ? 'eth_call' : 'starknet_call', 'ch-xs') }),
    body([
      chain === 'evm' ? field('ABI 来源', h('select', { id: 'evm-abi-preset' }, [
        h('option', { value: 'erc20', text: '预设：ERC-20 代币' }),
        h('option', { value: 'custom', text: '自定义 ABI JSON' }),
      ])) : null,
      chain === 'evm' ? h('div', { id: 'evm-abi-wrap', style: formVal('evm-abi-preset') === 'custom' ? '' : 'display:none' }, [
        h('textarea', { id: 'evm-abi-json', rows: '4', placeholder: '[{"type":"function","name":"greet","stateMutability":"view","inputs":[],"outputs":[{"type":"string"}]}]' }, [formVal('evm-abi-json')]),
      ]) : null,
      field('合约地址', input(`${chain}-contract`, { cls: 'mono', placeholder: '0x…', value: formVal(`${chain}-contract`), attrs: { style: 'font-size:11.5px' } })),
      field('方法名', input(`${chain}-method`, { cls: 'mono', placeholder: chain === 'evm' ? 'balanceOf / transfer / symbol' : 'balance_of / symbol / faucet', value: formVal(`${chain}-method`), attrs: { style: 'font-size:11.5px' } })),
      field('参数', input(`${chain}-args`, { cls: 'mono', placeholder: chain === 'evm' ? '逗号分隔；token 金额用人类可读单位' : 'felt hex（0x…），逗号分隔', value: formVal(`${chain}-args`), attrs: { style: 'font-size:11.5px' } })),
      h('div', { class: 'btn-row' }, [
        btn('读取', { cls: 'btn-s', id: `${chain}-read-btn`, attrs: { 'data-act': `${chain}-read` } }),
        btn('发起交易', { id: `${chain}-write-btn`, attrs: { 'data-act': `${chain}-write` } }),
      ]),
      errLine('contract-err'),
      out ? h('div', { id: `${chain}-read-result` }, [cd(`${out.signature ?? out.selector ?? '返回'}`, (out.values ?? []).map((v) => {
        const obj = v && typeof v === 'object';
        const shown = obj ? (v.human ?? v.raw) : v;
        const withRaw = obj && v.human != null && v.raw != null && String(v.human) !== String(v.raw);
        return lr(
          chain === 'evm' ? (v?.type ?? '返回') : '返回',
          withRaw ? `${shown}（raw ${v.raw}）` : String(shown ?? '—'),
        );
      }))]) : null,
      rt.gate?.chain === chain && rt.gate.kind === 'write' ? chainTxPreview(chain, rt.gate.preview) : null,
      h('p', { class: 'hint-s', style: 'text-align:left;margin-top:10px', text: '只读方法直接调用；非只读方法走交易确认路径（预览 → 签名 → 广播）。felt 参数用 hex。' }),
    ]),
  ], { aria: '合约' }));
  const preset = document.getElementById('evm-abi-preset');
  if (preset) {
    preset.value = formVal('evm-abi-preset') || 'erc20';
    preset.addEventListener('change', () => {
      rt.form['evm-abi-preset'] = preset.value;
      const w = document.getElementById('evm-abi-wrap');
      if (w) w.style.display = preset.value === 'custom' ? '' : 'none';
    });
  }
};

act('evm-read', () => chainRead('evm'));
act('stk-read', () => chainRead('stk'));
act('evm-write', () => chainWrite('evm'));
act('stk-write', () => chainWrite('stk'));

async function chainRead(chain) {
  const scope = currentScr();
  clearErr(scope);
  rt.gate = null;
  captureForm(`${chain}-contract`, `${chain}-method`, `${chain}-args`);
  const res = chain === 'evm'
    ? await send({
      type: CHAIN_API.evm.read,
      preset: document.getElementById('evm-abi-preset')?.value === 'erc20' ? 'erc20' : null,
      abiJson: document.getElementById('evm-abi-preset')?.value === 'custom' ? document.getElementById('evm-abi-json').value : null,
      contract: document.getElementById('evm-contract').value.trim(),
      method: document.getElementById('evm-method').value.trim(),
      args: splitArgs(document.getElementById('evm-args').value),
    })
    : await send({
      type: CHAIN_API.stk.read,
      contract: document.getElementById('stk-contract').value.trim(),
      functionName: document.getElementById('stk-method').value.trim(),
      calldata: splitArgs(document.getElementById('stk-args').value),
    });
  if (res?.error) { setErr(scope, res.error); render(); return; }
  rt.gate = { chain, kind: 'read', result: res };
  render();
}

async function chainWrite(chain) {
  const scope = currentScr();
  clearErr(scope);
  rt.gate = null;
  captureForm(`${chain}-contract`, `${chain}-method`, `${chain}-args`);
  const res = chain === 'evm'
    ? await send({
      type: CHAIN_API.evm.prepareContract,
      preset: document.getElementById('evm-abi-preset')?.value === 'erc20' ? 'erc20' : null,
      abiJson: document.getElementById('evm-abi-preset')?.value === 'custom' ? document.getElementById('evm-abi-json').value : null,
      contract: document.getElementById('evm-contract').value.trim(),
      method: document.getElementById('evm-method').value.trim(),
      args: splitArgs(document.getElementById('evm-args').value),
    })
    : await send({
      type: CHAIN_API.stk.prepareContract,
      to: document.getElementById('stk-contract').value.trim(),
      functionName: document.getElementById('stk-method').value.trim(),
      calldata: splitArgs(document.getElementById('stk-args').value),
    });
  if (res?.error) { setErr(scope, res.error); render(); return; }
  rt.gate = { chain, kind: 'write', preview: res.preview };
  render();
}

function splitArgs(raw) {
  const s = String(raw ?? '').trim();
  if (!s) return [];
  return s.split(',').map((x) => x.trim()).filter((x) => x.length > 0);
}

RENDERERS.history = async () => {
  const chain = rt.chain === 'zc' ? 'evm' : rt.chain;
  const api = CHAIN_API[chain];
  const st = await send({ type: api.getState });
  if (st?.error) { mount(chainErrorScr(chain, st.error)); return; }
  const cached = rt.history?.chain === chain ? rt.history.res : null;
  const wantExplorer = rt.history?.chain === chain ? rt.history.includeExplorer === true : false;
  const txs = cached?.txs ?? [];
  const buckets = historyBuckets(txs);
  const rows = (list) => (list.length === 0 ? [emptyBox('暂无交易记录')] : [cd(null, list.map((t) => {
    const c = txStatusChip(t.status);
    const self = (rt.overview?.layers ?? {})[layerKey(chain)]?.address;
    const dir = txDirection(t, self);
    return txRow({
      iconName: t.kind === 'contract' ? 'file' : dir === 'in' ? 'recv' : 'send',
      ticCls: t.status === 'failed' || t.status === 'reverted' ? 'bad' : c.cls === 'ch-felt' ? 'ok' : c.cls === 'ch-amb' ? 'warn' : 'blue',
      name: `${t.kind === 'contract' ? (t.methodLabel ?? '合约调用') : (dir === 'in' ? '接收' : '发送')} · ${fmtAmount(t.valueHuman ?? '0')}`,
      sub: `${shortAddr(t.hash, 10, 8)} · ${relTime(t.createdAtMs)}${t.source === 'explorer' ? ' · 链上' : ' · 本地'}`,
      amount: dir === 'in' ? fmtSigned(t.valueHuman ?? '0', { positive: true }) : fmtSigned(t.valueHuman ?? '0', { negative: true }),
      amountCls: dir === 'in' ? 'pos' : 'neg',
      chipNode: chip(c.text, `ch-xs ${c.cls}`),
    });
  }), { cls: 'rows' })]);
  mount(scr([
    subHeader('交易记录', { right: chip(chain === 'evm' ? 'Ethereum' : 'Starknet', 'ch-xs') }),
    body([
      h('div', { class: 'row', style: 'margin-bottom:12px' }, [
        h('div', { class: 'grow' }, [
          h('b', { style: 'font-size:12px;font-weight:600', text: '合并 Explorer 数据' }),
          h('div', { class: 'ar-s', text: '本地账本 + Etherscan 兼容 txlist' }),
        ]),
        h('span', { class: `sw2 ${wantExplorer ? 'on' : ''}`, role: 'switch', 'aria-checked': wantExplorer ? 'true' : 'false', id: `${chain}-history-explorer`, 'data-act': `${chain}-history-explorer` }),
      ]),
      h('div', { class: 'seg' }, [
        h('button', { class: 'on', type: 'button', 'data-seg': 'all', id: `h-seg-all`, text: `全部 ${buckets.all.length}` }),
        h('button', { type: 'button', 'data-seg': 'tx', id: `h-seg-tx`, text: `转账 ${buckets.tx.length}` }),
        h('button', { type: 'button', 'data-seg': 'c', id: `h-seg-c`, text: `合约 ${buckets.c.length}` }),
      ]),
      h('div', { 'data-pane': 'all', id: `${chain}-history-list` }, rows(buckets.all)),
      h('div', { 'data-pane': 'tx', style: 'display:none' }, rows(buckets.tx)),
      h('div', { 'data-pane': 'c', style: 'display:none' }, rows(buckets.c)),
      btn(cached ? '重新对账' : '刷新记录', { cls: 'btn-s', id: `${chain}-history-btn`, attrs: { 'data-act': `${chain}-history`, style: 'margin-top:2px' } }),
      errLine('history-err'),
      cached?.explorerNote ? banner('amb', '链上探索器记录未合并', `${cached.explorerNote} —— 本地记录照常展示，不做静默合并。`) : null,
      (cached?.pendingReconciled ?? 0) > 0 ? okLine() : null,
      h('p', { class: 'hint-s', style: 'text-align:left;margin-top:8px', text: '来源用芯片区分（本地 / 链上）；两者冲突时以链上回执为准，并把差异原样列出来。' }),
    ]),
  ], { aria: '交易记录' }));
  if ((cached?.pendingReconciled ?? 0) > 0) {
    const o = okLine();
    o.textContent = `本轮对账更新 ${cached.pendingReconciled} 笔待确认交易。`;
  }
};

act('evm-history-explorer', () => toggleExplorerFlag('evm'));
act('stk-history-explorer', () => toggleExplorerFlag('stk'));

async function toggleExplorerFlag(chain) {
  rt.history = { chain, includeExplorer: !(rt.history?.chain === chain && rt.history?.includeExplorer), res: rt.history?.chain === chain ? rt.history.res : null };
  render();
}

act('evm-history', () => loadHistory('evm'));
act('stk-history', () => loadHistory('stk'));

async function loadHistory(chain) {
  const scope = currentScr();
  clearErr(scope);
  const includeExplorer = rt.history?.chain === chain ? rt.history.includeExplorer === true : false;
  const type = CHAIN_API[chain].history;
  const res = await send({ type, includeExplorer });
  if (res?.error) { setErr(scope, res.error); return; }
  rt.history = { chain, includeExplorer, res };
  render();
}

RENDERERS.manage = async () => {
  const chain = rt.chain === 'zc' ? 'evm' : rt.chain;
  const api = CHAIN_API[chain];
  const st = await send({ type: api.getState });
  if (st?.error) { mount(chainErrorScr(chain, st.error)); return; }
  const acct = (st.accounts ?? []).find((a) => a.id === st.activeAccountId);
  const net = (st.networks ?? []).find((n) => n.id === st.networkId);
  mount(scr([
    subHeader('账户管理'),
    body([
      cd(null, [h('div', { class: 'row', style: 'gap:12px' }, [
        h('span', { class: 'av', style: 'width:38px;height:38px;font-size:15px', text: (acct?.label ?? 'A').slice(0, 1).toUpperCase() }),
        h('div', { class: 'grow', style: 'min-width:0' }, [
          h('div', { class: 'ar-n', style: 'font-size:13px' }, [acct?.label ?? '未命名', st.unlocked ? chip('已解锁', 'ch-felt ch-xs') : chip('已锁定', 'ch-amb ch-xs')]),
          h('div', { class: 'ar-s', id: `${chain}-address`, text: acct?.address ?? st.address ?? '—' }),
        ]),
      ])]),
      secT('安全'),
      cd(null, [
        h('details', { id: `${chain}-export-details` }, [
          h('summary', { text: '导出私钥（口令确认后展开）' }),
          input(`${chain}-export-pw`, { type: 'password', placeholder: '口令' }),
          errLine(`${chain}-export-err`),
          btn('显示私钥（谨慎）', { cls: 'btn-o', id: `${chain}-export-btn`, attrs: { 'data-act': `${chain}-export`, style: 'margin-top:6px' } }),
          h('div', { id: `${chain}-export-out` }),
        ]),
        h('details', { id: `${chain}-cpw-details` }, [
          h('summary', { text: '修改口令（本层 keystore 重派生）' }),
          input(`${chain}-cpw-current`, { type: 'password', placeholder: '当前口令' }),
          input(`${chain}-cpw-next`, { type: 'password', placeholder: '新口令（≥ 8 位）' }),
          errLine(`${chain}-cpw-err`),
          btn('修改口令', { cls: 'btn-s', id: `${chain}-cpw-btn`, attrs: { 'data-act': `${chain}-cpw`, style: 'margin-top:6px' } }),
        ]),
        mi({ iconName: 'lock', title: '锁定本层', sub: '立即清除内存中的会话', attrs: { 'data-act': `${chain}-lock`, id: `${chain}-lock-btn` } }),
      ], { cls: 'rows' }),
      secT('网络'),
      cd(null, [
        field('RPC 覆盖', input(`${chain}-rpc-input`, { cls: 'mono', placeholder: net?.rpcUrl ?? 'http://…（留空恢复默认）', value: net?.rpcOverridden ? (net?.rpcUrl ?? '') : '', attrs: { style: 'font-size:11px' } })),
        errLine(`${chain}-rpc-err`),
        btn('保存 RPC（留空恢复默认）', { cls: 'btn-s', id: `${chain}-rpc-save`, attrs: { 'data-act': `${chain}-rpc-save` } }),
        field('Explorer API 覆盖', input(`${chain}-explorer-input`, { cls: 'mono', placeholder: 'Etherscan 兼容 txlist 端点（可选）', value: net?.explorerApiUrl ?? '', attrs: { style: 'font-size:11px;margin-top:12px' } })),
        errLine(`${chain}-explorer-err`),
        btn('保存 Explorer API（留空清除）', { cls: 'btn-s', id: `${chain}-explorer-save`, attrs: { 'data-act': `${chain}-explorer-save` } }),
      ]),
      secT('危险区', { danger: true }),
      cd(null, [
        mi({
          iconName: 'trash', title: '删除当前账户', danger: true,
          sub: '需二次确认；导出私钥前请先备份',
          attrs: { 'data-act': `${chain}-remove-open`, id: `${chain}-remove-open` },
        }),
      ], { cls: 'rows', more: null }),
      h('div', { class: 'foot', text: '本机 keystore：PBKDF2-SHA256 600k + AES-256-GCM · 私钥只在后台内存会话，落盘仅密文 · 无云端副本' }),
    ]),
  ], { aria: '账户管理' }));
};

function chainErrorScr(chain, err) {
  const s = scr([subHeader(`${chainName(chain)} 账户`), body([errLine(`${chain}-err`)])], { aria: '错误' });
  setTimeout(() => setErr(s, err), 0);
  return s;
}

act('evm-lock', () => chainLock('evm'));
act('stk-lock', () => chainLock('stk'));
async function chainLock(chain) {
  await send({ type: CHAIN_API[chain].lock });
  if (chain === 'evm') rt.evmInfo = null; else rt.stkInfo = null;
  toast(`${chainName(chain)} 层已锁定`);
  rt.screen = 'acct';
  render();
}

act('evm-unlock', () => chainUnlock('evm'));
act('stk-unlock', () => chainUnlock('stk'));
async function chainUnlock(chain) {
  const scope = currentScr();
  const pw = document.getElementById(`${chain}-unlock-pw`);
  clearErr(scope);
  const st = await send({ type: CHAIN_API[chain].getState });
  const res = await send({ type: CHAIN_API[chain].unlock, accountId: st.activeAccountId, password: pw?.value ?? '' });
  if (pw) pw.value = '';
  if (res?.error) { setErr(scope, res.error); return; }
  toast(`${chainName(chain)} 层已解锁`);
  render();
}

act('evm-create', () => chainCreate('evm'));
act('stk-create', () => chainCreate('stk'));
async function chainCreate(chain) {
  const scope = currentScr();
  clearErr(scope);
  const p1 = document.getElementById(`${chain}-pw`);
  const p2 = document.getElementById(`${chain}-pw2`);
  if ((p1?.value ?? '').length < 8) { setErr(scope, null, '口令太短（≥ 8 字符）'); return; }
  if (p1.value !== p2.value) { setErr(scope, null, '两次口令不一致'); return; }
  const res = await send({ type: CHAIN_API[chain].create, password: p1.value, label: document.getElementById(`${chain}-label`)?.value });
  p1.value = ''; p2.value = '';
  if (res?.error) { setErr(scope, res.error); return; }
  toast(`${chainName(chain)} 账户已创建并解锁`);
  render();
}

act('evm-import', () => chainImport('evm'));
act('stk-import', () => chainImport('stk'));
async function chainImport(chain) {
  const scope = currentScr();
  clearErr(scope);
  const key = document.getElementById(`${chain}-import-key`);
  const pw = document.getElementById(`${chain}-import-pw`);
  const res = await send({ type: CHAIN_API[chain].importKey, privateKey: key?.value.trim() ?? '', password: pw?.value ?? '' });
  if (key) key.value = '';
  if (pw) pw.value = '';
  if (res?.error) { setErr(scope, res.error); return; }
  toast(`已导入 ${chainName(chain)} 账户 ${shortAddr(res.address ?? '', 8, 6)}`);
  render();
}

act('evm-export', () => chainExport('evm'));
act('stk-export', () => chainExport('stk'));
async function chainExport(chain) {
  const details = document.getElementById(`${chain}-export-details`);
  const err = document.getElementById(`${chain}-export-err`);
  const out = document.getElementById(`${chain}-export-out`);
  if (err) err.textContent = '';
  out.replaceChildren();
  const pw = document.getElementById(`${chain}-export-pw`);
  const res = await send({ type: CHAIN_API[chain].exportKey, password: pw?.value ?? '' });
  if (pw) pw.value = '';
  if (res?.error) { if (err) err.textContent = errorText(res.error); return; }
  const keyId = `${chain}-exported-key`;
  out.append(
    h('div', { class: 'raw', id: keyId, text: res.privateKey }),
    btn('复制私钥', { cls: 'btn-s btn-sm', id: `${chain}-export-copy`, attrs: { 'data-copy': `#${keyId}`, style: 'margin-top:6px' } }),
    banner('bad', '任何持有该私钥的人都能完全控制此账户', '切勿粘贴到不受信任的页面；展示后请手动清除。'),
  );
}

act('evm-cpw', () => chainChangePw('evm'));
act('stk-cpw', () => chainChangePw('stk'));
async function chainChangePw(chain) {
  const err = document.getElementById(`${chain}-cpw-err`);
  if (err) err.textContent = '';
  const cur = document.getElementById(`${chain}-cpw-current`);
  const next = document.getElementById(`${chain}-cpw-next`);
  if ((next?.value ?? '').length < 8) { if (err) err.textContent = '新口令太短（≥ 8 字符）'; return; }
  const res = await send({ type: CHAIN_API[chain].changePw, current: cur?.value ?? '', next: next?.value ?? '' });
  if (cur) cur.value = '';
  if (next) next.value = '';
  if (res?.error) { if (err) err.textContent = errorText(res.error); return; }
  toast('口令已修改（keystore 已用新口令重加密）');
}

act('evm-rpc-save', () => chainSaveRpc('evm'));
act('stk-rpc-save', () => chainSaveRpc('stk'));
async function chainSaveRpc(chain) {
  const err = document.getElementById(`${chain}-rpc-err`);
  if (err) err.textContent = '';
  const url = document.getElementById(`${chain}-rpc-input`).value.trim();
  const st = await send({ type: CHAIN_API[chain].getState });
  const key = chain === 'evm' ? 'chainIdHex' : 'networkId';
  const net = (st.networks ?? []).find((n) => n.id === st.networkId);
  const res = await send({ type: CHAIN_API[chain].setRpc, [key === 'chainIdHex' ? 'chainIdHex' : 'networkId']: net?.[key] ?? net?.id, rpcUrl: url });
  if (res?.error) { if (err) err.textContent = errorText(res.error); return; }
  if (chain === 'evm') rt.evmInfo = null; else rt.stkInfo = null;
  toast('RPC 已更新');
  render();
}

act('evm-explorer-save', () => chainSaveExplorer('evm'));
act('stk-explorer-save', () => chainSaveExplorer('stk'));
async function chainSaveExplorer(chain) {
  const err = document.getElementById(`${chain}-explorer-err`);
  if (err) err.textContent = '';
  const apiUrl = document.getElementById(`${chain}-explorer-input`).value.trim();
  const st = await send({ type: CHAIN_API[chain].getState });
  const net = (st.networks ?? []).find((n) => n.id === st.networkId);
  const res = await send({ type: CHAIN_API[chain].setExplorer, ...(chain === 'evm' ? { chainIdHex: net?.chainIdHex } : { networkId: net?.id }), apiUrl });
  if (res?.error) { if (err) err.textContent = errorText(res.error); return; }
  toast('Explorer API 已更新');
  render();
}

act('evm-remove-open', () => chainRemoveOpen('evm'));
act('stk-remove-open', () => chainRemoveOpen('stk'));

function chainRemoveOpen(chain) {
  openModalNode(`删除 ${chainName(chain)} 账户？`, [
    h('p', { text: '该账户的私钥将从本机 keystore 永久移除。若没有备份，资产无法找回。此操作与其他两层无关。' }),
    input(`${chain}-remove-confirm`, { type: 'text', placeholder: '输入 DELETE 以确认' }),
    errLine(`${chain}-remove-err`),
    h('div', { class: 'btn-row', style: 'margin-top:12px' }, [
      btn('取消', { cls: 'btn-g', attrs: { 'data-close': '1' } }),
      btn('确认删除', { cls: 'btn-d', id: `${chain}-remove-btn`, attrs: { 'data-act': `${chain}-remove`, 'data-chain': chain } }),
    ]),
  ]);
}

act('evm-remove', (node) => chainRemove(node));
act('stk-remove', (node) => chainRemove(node));

async function chainRemove(node) {
  const chain = node.getAttribute('data-chain');
  const confirm = document.getElementById(`${chain}-remove-confirm`);
  const err = document.getElementById(`${chain}-remove-err`);
  if (confirm?.value.trim().toUpperCase() !== 'DELETE') { if (err) err.textContent = '请输入 DELETE 确认'; return; }
  const st = await send({ type: CHAIN_API[chain].getState });
  const res = await send({ type: CHAIN_API[chain].remove, accountId: st.activeAccountId });
  if (res?.error) { if (err) err.textContent = errorText(res.error); return; }
  closeAllSheets();
  toast('账户已删除');
  rt.screen = 'acct';
  render();
}

// ---------------------------------------------------------------------------
// 17 凭证簿（方向 B v0.2 新增屏：把"结算可证"提为一等 tab）
// ---------------------------------------------------------------------------

const PROOF_LOG_KEY = 'zchain.proofLog';

async function readProofLog() {
  try {
    const { [PROOF_LOG_KEY]: v } = await chrome.storage.local.get(PROOF_LOG_KEY);
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

RENDERERS.proofs = async (ov) => {
  const zcUnlocked = ov.layers?.zchain?.unlocked;
  const [notesRes, receiptsRes, log] = await Promise.all([
    zcUnlocked ? send({ type: 'popup:getNotes' }) : Promise.resolve(null),
    send({ type: 'popup:receipts' }),
    readProofLog(),
  ]);
  const notes = notesRes && !notesRes.error ? notesRes : null;
  const ladder = notes ? proofLadder([...(notes.notes ?? []), ...(notes.realNotes ?? [])]) : null;
  const buckets = receiptBuckets(receiptsRes?.receipts ?? []);
  const waitReverify = buckets.all.filter((r) => r.status !== 'included').slice(0, 5);
  const weakest = ladder?.weakest ?? null;
  const steps = ladderSteps({ current: weakest, outcome: weakest && weakest !== 'finalized' ? 'wait' : 'ok' });
  const reachedFinalized = ladder?.counts?.finalized ?? 0;

  mount(scr([
    docHeader({
      kind: 'Proofs',
      netText: 'engine stwo',
      netAct: null,
      addrText: `最近 ${log.length} 次本地复验 · ${ladder ? `${ladder.total} 张 note 带凭证` : '解锁后可见 note 级凭证'}`,
    }),
    body([
      cd('凭证分布', [
        rail(steps, { capLeft: '阶梯锚定在 note 上：pending → soft → proven → finalized' }),
        lr('已达 finalized', `${fmtAmount(reachedFinalized)} / ${fmtAmount(ladder?.total ?? 0)}`, { dim: !reachedFinalized }),
        weakest && weakest !== 'finalized'
          ? lr('短板停在', weakest, { vKids: [h('span', { text: weakest }), chip('未达 REAL 门槛', 'ch-amb ch-xs')] })
          : null,
        notes ? null : banner('amb', 'ZChain 层未解锁', 'note 级凭证层级只在解锁后可见（来自 wallet-core 账本，不做推测）。'),
      ]),
      secT('待复验'),
      waitReverify.length === 0
        ? emptyBox('无待复验项：所有回执都已登记为 included')
        : cd(null, waitReverify.map((r) => mi({
          iconName: r.view?.pastDeadline ? 'bolt' : 'shield',
          icStyle: r.view?.pastDeadline ? 'color:var(--amb);border-color:var(--amb-rl);background:var(--amb-w)' : '',
          title: `${kindLabel(r.kind)} · ${shortAddr(r.digest, 8, 6)}`,
          sub: r.view?.pastDeadline ? '超出 deadline · ForceInclude 仅协议路径（未实现提交）' : `${r.status} 未 included · ${relTime(r.signedAtMs)}`,
          attrs: { 'data-nav': 'zc-portal', id: 'proofs-wait-item' },
        })), { cls: 'rows' }),
      secT('已复验'),
      log.length === 0
        ? emptyBox('本设备还没有复验记录：在 Proof Portal 输入 hand binding 验证一手牌')
        : cd(null, log.slice(0, 6).map((e) => lr(
          shortAddr(e.binding ?? '', 10, 8),
          '',
          { vKids: [h('span', { text: `${e.conclusion === 'verified' ? 'verified' : e.conclusion ?? '—'} · ` }), chip(`${(e.elapsedMs ?? 0).toFixed(0)}ms`, `ch-xs ${e.conclusion === 'verified' ? 'ch-felt' : 'ch-bad'}`)] },
        )), { cls: 'rows' }),
      banner('info', '验证在本地完成', '证明文件与结算明细由网关拉取，复验在 wallet-core / stwo wasm 本地执行；不依赖服务端「已验证」结论。'),
      h('p', { class: 'hint-s', style: 'text-align:left', text: '阶梯是凭证状态（锚定在 note 上）；回执的 signed → seen → included 是投递状态。两者笔触刻意不同，不得混用。' }),
      btn('打开 Proof Portal', { cls: 'btn-s', id: 'proofs-open-portal', attrs: { 'data-nav': 'zc-portal', style: 'margin-top:10px' }, icon: 'shield' }),
    ]),
    tabsBar(),
  ], { aria: '凭证簿' }));
};

// ---------------------------------------------------------------------------
// 18 设置 · 能力矩阵
// ---------------------------------------------------------------------------

RENDERERS.settings = async (ov) => {
  const st = await send({ type: 'popup:getState' }).catch(() => ({}));
  const manifest = chrome.runtime.getManifest();
  const lockMin = Math.round((ov.autoLockMs ?? 900_000) / 60_000);
  mount(scr([
    subHeader('设置'),
    body([
      secT('通用'),
      cd(null, [
        mi({ iconName: 'clock', title: '自动锁定', sub: '无操作即锁；后台被回收同样锁定（fail-closed）', right: chip(`${lockMin} min`, 'ch-xs mono'), attrs: { 'data-toast': `自动锁定 ${lockMin} 分钟：由后台常量 AUTO_LOCK_MS 决定，本版本不提供 UI 改写` } }),
        h('div', { class: 'mi' }, [
          h('span', { class: 'mi-ic' }, [ic('book', 'ic ic-s')]),
          h('span', { class: 'grow' }, [h('b', { text: '外观底面' }), h('span', { text: '纸白账簿 / 夜场账簿（同一套 token 的两种底色）' })]),
          h('button', { class: 'ch ch-xs mono', type: 'button', 'data-act': 'toggle-ground', id: 'set-ground', text: rt.ground === 'night' ? '夜场' : '纸白' }),
        ]),
        h('div', { class: 'mi' }, [
          h('span', { class: 'mi-ic' }, [ic('eye', 'ic ic-s')]),
          h('span', { class: 'grow' }, [h('b', { text: '金额显示' }), h('span', { text: '公共场所隐藏余额数字（只影响展示）' })]),
          h('span', { class: `sw2 ${rt.hideAmount ? 'on' : ''}`, role: 'switch', 'aria-checked': rt.hideAmount ? 'true' : 'false', 'data-act': 'toggle-amount', id: 'set-hide' }),
        ]),
        mi({ iconName: 'wallet', title: '货币计价', sub: '无价格源 / 预言机接入：不做任何法币折算', right: chip('未接入', 'ch-xs ch-bad'), attrs: { 'data-toast': '价格源未接入：界面不显示折算值，避免给出看似精确的假数字' } }),
      ], { cls: 'rows' }),
      secT('网关'),
      cd('Proof Portal 网关', [
        h('p', { class: 'hint-s', style: 'text-align:left;margin:0 0 8px', text: `当前网络 ${st.chainId ?? '—'}：结算明细与证明归档的拉取地址。留空 = 恢复该网络默认。` }),
        input('gateway-input', { cls: 'mono', value: st.gatewayUrl ?? '', placeholder: 'http://127.0.0.1:18900', attrs: { style: 'font-size:11px' } }),
        errLine('gw-err'),
        btn('保存网关地址', { cls: 'btn-s', id: 'gateway-save', attrs: { 'data-act': 'set-gateway' } }),
      ]),
      secT('安全与备份'),
      cd(null, [
        h('details', {}, [
          h('summary', { text: '备份导出（.zcbk · 仅 ZChain 层）' }),
          input('backup-export-pw', { type: 'password', placeholder: '备份口令（≥ 8 位，可与解锁口令不同）' }),
          errLine('bk-err'),
          btn('导出备份文件', { cls: 'btn-s', id: 'backup-export-btn', attrs: { 'data-act': 'backup-export', style: 'margin-top:6px' } }),
          h('p', { class: 'hint-s', style: 'text-align:left;margin-top:6px', text: 'ZCBK v1：REAL/PLAY 双库 + keystore 信封 + 索引自检，Argon2id + ChaCha20-Poly1305 加密。' }),
        ]),
        mi({ iconName: 'ul', title: '从备份恢复', sub: 'Argon2id 本地解密 · 恢复为新的锁定账户', attrs: { 'data-nav': 'import' } }),
        mi({ iconName: 'key', title: '授权簿 / 会话密钥', sub: '按 origin 撤销 dapp 授权与委托密钥', attrs: { 'data-nav': 'zc-sessions' } }),
        mi({ iconName: 'file', title: '能力矩阵', sub: '各层能力与红线的如实说明', attrs: { 'data-open': 'mdl-cap', id: 'set-capability' } }),
      ], { cls: 'rows' }),
      secT('关于'),
      cd(null, [
        h('div', { class: 'mi' }, [
          h('span', { class: 'mi-ic' }, [ic('info', 'ic ic-s')]),
          h('span', { class: 'grow' }, [h('b', { text: '版本' }), h('span', { text: `MV3 · DevNet 形态 · provider ${ov.providerVersion ?? '—'}` })]),
          chip(manifest.version, 'ch-xs mono'),
        ]),
        mi({ iconName: 'ext', title: 'Proof Portal 独立页', sub: '逐阶段明细 / 主机权限授予', attrs: { 'data-act': 'portal-open' } }),
      ], { cls: 'rows' }),
      banner('bad', '未通过第三方审计', '「可验证」指密码学与结算证明可被独立复核，不等于已审计；本界面不出现任何审计徽章。'),
      h('div', { class: 'foot', text: 'ZChain Wallet · 桌上飞快，结算可证\nFast at the table. Verifiable at settlement.' }),
    ]),
    mdlCapability(),
  ], { aria: '设置' }));
};

function mdlCapability() {
  return h('div', { class: 'mdl-bg', id: 'mdl-cap' }, [
    h('div', { class: 'mdl' }, [
      h('h3', { text: '能力矩阵' }),
      h('p', { text: '逐层能力与红线，按 extension 的交付面如实列举；不为好看放宽。' }),
      h('div', { id: 'cap-body' }, [emptyBox('加载中…')]),
      h('div', { class: 'btn-row', style: 'margin-top:14px' }, [btn('知道了', { cls: 'btn-p', attrs: { 'data-close': '1' } })]),
    ]),
  ]);
}

// 能力矩阵按需加载：请求一次、缓存结果，之后每次渲染都往当前节点补一遍
// （render 会重建 DOM，"已加载"标记若挂在节点上就会留下永久「加载中…」）。
const capLoader = { cache: null, busy: false };
$view.addEventListener('click', (e) => {
  if (e.target.closest('[data-open="mdl-cap"]')) ensureCapMatrix();
});

const CAP_RED_LINES = [
  ['ZChain', 'GAME 域可签可转；REAL 仅隔离展示，提现预览 canSubmit 恒 false'],
  ['EVM', '转账与合约写入可签名广播（EIP-155 + chainId 校验）；不签 note spend'],
  ['Starknet', 'invoke v1 + devnet 水龙头；SNIP-12 授权面已备，链上 admission 未开放'],
  ['网络', 'mainnet 刻意不注册 → NetworkUnsupported；devnet/testnet 才可选'],
  ['边界', '盲签拒绝；私钥 / 助记词 / nullifier 不出边界；网关水位原样展示、不推进'],
  ['会话', '三层共用口令、会话彼此独立；后台被回收即锁定（fail-closed）'],
];

async function ensureCapMatrix() {
  const bodyEl = document.getElementById('cap-body');
  if (!bodyEl || !bodyEl.querySelector('.empty') || capLoader.busy) return;
  capLoader.busy = true;
  if (!capLoader.cache) {
    try {
      const res = await send({ type: 'popup:capabilityMatrix' });
      if (!res?.matrix) {
        bodyEl.replaceChildren(h('div', { class: 'errx', text: `能力矩阵不可用：${errorText(res?.error ?? { code: 'NoMatrix' })}` }));
        capLoader.busy = false;
        return;
      }
      capLoader.cache = res.matrix;
    } catch (err) {
      bodyEl.replaceChildren(h('div', { class: 'errx', text: `能力矩阵请求失败：${String(err?.message ?? err)}` }));
      capLoader.busy = false;
      return;
    }
  }
  const m = capLoader.cache;
  bodyEl.replaceChildren();
  for (const [k, v] of CAP_RED_LINES) bodyEl.appendChild(h('div', { class: 'rsn' }, [chip(k, 'ch-xs mono'), h('span', { text: v })]));
  for (const row of m.rows ?? []) {
    bodyEl.appendChild(h('div', { class: 'rsn', style: 'margin-top:6px' }, [
      ic('swap', 'ic ic-s'),
      h('span', {}, [h('b', { class: 'mono', text: row.protocol }), ` ${row.active ? '· 启用' : '· 未激活'} —— ${row.summary ?? ''}`]),
    ]));
  }
  capLoader.busy = false;
}

act('toggle-ground', () => {
  rt.ground = nextGround(rt.ground);
  applyGround();
  persistPrefs();
  render();
});

act('set-gateway', async () => {
  const st = await send({ type: 'popup:getState' });
  const err = document.getElementById('gw-err');
  if (err) err.textContent = '';
  const res = await send({ type: 'popup:setGateway', chainId: st.chainId, gatewayUrl: document.getElementById('gateway-input').value.trim() });
  if (res?.error) { if (err) err.textContent = errorText(res.error); return; }
  toast('网关已保存');
  render();
});

act('backup-export', async () => {
  const err = document.getElementById('bk-err');
  if (err) err.textContent = '';
  const pw = document.getElementById('backup-export-pw');
  if ((pw?.value ?? '').length < 8) { if (err) err.textContent = '口令太短（≥ 8 字符）'; return; }
  const res = await send({ type: 'popup:backupExport', password: pw.value });
  pw.value = '';
  if (res?.error) { if (err) err.textContent = errorText(res.error); return; }
  const bytes = new Uint8Array(res.backupHex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(res.backupHex.slice(i * 2, i * 2 + 2), 16);
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
  const a = h('a', { href: url, download: `zchain-backup-${res.createdUnix ?? Date.now()}.zcbk` });
  a.click();
  URL.revokeObjectURL(url);
  toast(`备份已导出（REAL ${res.notes?.real ?? 0} + PLAY ${res.notes?.play ?? 0} notes）`);
});

// ---------------------------------------------------------------------------
// 启动
// ---------------------------------------------------------------------------

loadPrefs();
render();





