// =============================================================================
// extension/popup/popup.js — ZChain Wallet UI（Extension 0.4）
//
// 0.2 视图面：
// - 多账户：账户列表（切换/新建/逐账户解锁；锁定当前不影响其他账户）；
// - 网络切换：devnet/testnet 选择 + 二步确认；换网确认请求卡（from → to）；
// - REAL/PLAY 物理分栏：余额分栏 + 分列 note 列表；REAL 侧消费 wallet-core
//   display.rs 展示门（claim 恒隐藏 + 托管风险提示常显；不暗示可提现）；
// - 备份恢复：加密导出（口令 → ZCBK 文件下载）/ 导入（文件+口令 → fail-closed）；
// - 交易回执：inclusion 状态位（signed → seen → included；超 deadline 提示
//   ForceInclude——仅展示协议状态，无提交路径）；
// - proof portal 入口（独立扩展页 portal/portal.html）。
//
// 0.3 视图面：
// - 会话密钥（SNIP-12 授权）：创建授权（delegated key 生成走 wallet-core、
//   scope 默认低风险集、单笔/每日限额、桌白名单、有效期）→ SNIP-12 授权
//   摘要确认 → devnet 入口形态登记 → 撤销（粘滞）；
// - REAL 提现预览（展示态）：逐字段预览 + finality 聚合，提交恒禁用。
//
// 0.4 视图面：
// - 授权簿/registry：origin 权限列出/撤销；会话密钥列表（scope/限额/桌
//   白名单/到期/撤销）；
// - 钱包能力矩阵：EIP-1193 / WalletConnect / Starknet 能力探测结构化展示。
//
// 签名预览字段严格对齐 plan §6.12.4 / wallet-core SigningPreview（0.1 起不变）。
//
// 日志纪律（WALLET-ACC-4）：本文件不使用 console 输出任何请求内容；
// 密码只存在于表单值并直接传给后台，不落 storage、不入日志。
//
// TE-M5：资产分栏升级——REAL 域（NATIVE/USDT/USDC 三列）/ GAME 域
// （遗留 PLAY + 已注册 GTS 游戏币列表）分组展示；余额与 note/结算记录
// 带资产徽章。token 名称解析表集中在 common/networks.js（网络配置级），
// 分组/徽章逻辑在 common/assets.js（纯函数，node --test 覆盖）；本文件
// 只做 DOM 编排，不定义第二张名称表。
// =============================================================================

import { assetBadge, groupBalances, summarizeGatewayAssets } from '../common/assets.js';
import { fetchAssetSummary } from '../common/portal.js';

const $view = document.getElementById('view');
const $net = document.getElementById('net-badge');

const send = (m) => chrome.runtime.sendMessage(m);

const el = (tag, attrs = {}, text = '') => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  if (text) n.textContent = text;
  return n;
};

function card(title) {
  const c = el('div', { class: 'card' });
  if (title) c.appendChild(el('h2', {}, title));
  return c;
}

function row(k, v, mono = false) {
  const r = el('div', { class: 'row' });
  r.appendChild(el('span', { class: 'k' }, k));
  const val = el('span', { class: mono ? 'v mono' : 'v' }, String(v));
  r.appendChild(val);
  return r;
}

function errBox(msg) {
  const e = el('div', { class: 'err' });
  e.textContent = msg ?? '';
  e.dataset.live = '1';
  return e;
}

function shortHex(h, head = 10, tail = 6) {
  if (typeof h !== 'string') return '';
  return h.length <= head + tail + 1 ? h : `${h.slice(0, head)}…${h.slice(-tail)}`;
}

function badge(text, cls) {
  return el('span', { class: `badge ${cls}` }, text);
}

// ---------------------------------------------------------------------------
// 渲染
// ---------------------------------------------------------------------------

async function render() {
  const state = await send({ type: 'popup:getState' });
  $net.textContent = `${state.networkKind} · ${state.chainId}`;
  $net.className = `badge badge-${state.networkKind}`;
  $view.replaceChildren();

  if (!state.hasKeystore) return renderCreate(state);
  if (!state.unlocked) return renderLocked(state);
  await renderAccount(state);
  await renderPending();
}

// ---- 创建钱包 / 新建账户 ----
function renderCreate(state) {
  const first = !state.hasKeystore;
  const c = card(first ? '创建钱包（本地 keystore）' : '新建账户');
  const warn = el('div', { class: 'warn-box' },
    first
      ? 'Extension 0.4.0-alpha：PLAY 签名面（devnet/testnet）；REAL 仅隔离展示。口令用于 Argon2id 派生 KEK 加密 owner key 与 DEK（wallet-core）；口令丢失无法恢复。'
      : '新建账户会切换到该账户（wasm 会话单槽）：当前账户自动锁定（密文保留），可随时用各自口令切回。');
  c.appendChild(warn);
  if (!first) {
    const label = el('input', { type: 'text', id: 'acct-label', placeholder: '账户标签（可选）' });
    c.appendChild(label);
  }
  const p1 = el('input', { type: 'password', id: 'pw', placeholder: '口令（≥ 8 字符）' });
  const p2 = el('input', { type: 'password', id: 'pw2', placeholder: '重复口令' });
  const err = errBox();
  const btn = el('button', {}, first ? '创建（真实 Argon2id + secp256k1）' : '创建新账户');
  btn.addEventListener('click', async () => {
    if (p1.value.length < 8) { err.textContent = '口令太短（≥ 8 字符）'; return; }
    if (p1.value !== p2.value) { err.textContent = '两次口令不一致'; return; }
    btn.disabled = true;
    const res = await send({
      type: 'popup:create',
      password: p1.value,
      label: document.getElementById('acct-label')?.value,
    });
    if (res?.error) { err.textContent = `${res.error.code}: ${res.error.reason}`; btn.disabled = false; return; }
    p1.value = ''; p2.value = '';
    render();
  });
  c.append(p1, p2, err, btn);
  if (first) c.appendChild(renderImportCard());
  $view.appendChild(c);
}

// ---- 锁定态：账户切换 + 解锁 ----
function renderLocked(state) {
  if ((state.accounts ?? []).length > 1 || state.activeAccountId) {
    $view.appendChild(renderAccountList(state));
  }
  const acct = (state.accounts ?? []).find((a) => a.id === state.activeAccountId);
  const c = card(`解锁${acct ? `：${acct.label}` : ''}`);
  const p = el('input', { type: 'password', id: 'pw', placeholder: '口令' });
  const err = errBox();
  const btn = el('button', {}, '解锁');
  btn.addEventListener('click', async () => {
    btn.disabled = true;
    const res = await send({ type: 'popup:unlock', accountId: state.activeAccountId, password: p.value });
    btn.disabled = false;
    p.value = ''; // 口令不驻留 DOM
    if (res?.error) {
      err.textContent = res.error.code === 'BadPassword'
        ? '口令错误（fail-closed）'
        : `${res.error.code}: ${res.error.reason}`;
      return;
    }
    render();
  });
  c.append(p, err, btn);
  $view.appendChild(c);
  $view.appendChild(renderNewAccountEntry());
  $view.appendChild(renderImportCard());
}

function renderNewAccountEntry() {
  const c = el('div', { class: 'card' });
  const b = el('button', { class: 'secondary' }, '+ 新建账户');
  b.addEventListener('click', () => renderCreate({ hasKeystore: true }));
  c.appendChild(b);
  return c;
}

// ---- 账户列表（多账户切换） ----
function renderAccountList(state) {
  const c = card('账户');
  const ul = el('ul', { class: 'acct-list' });
  for (const a of state.accounts ?? []) {
    const li = el('li', { class: a.active ? 'active' : '' });
    const who = el('div', { class: 'who' });
    who.appendChild(el('div', { class: 'lbl' }, `${a.label}${a.active ? ' · 当前' : ''}`));
    who.appendChild(el('div', { class: 'pk mono' }, `${a.networkId} · ${shortHex(a.publicKey ?? '', 8, 4) || '（公钥解锁后可见）'}`));
    li.appendChild(who);
    if (!a.active) {
      const sw = el('button', { class: 'secondary' }, '切换');
      sw.addEventListener('click', async () => {
        sw.disabled = true;
        // 切换 = 锁定当前会话 + 选中目标账户（目标保持锁定，需口令解锁）。
        await send({ type: 'popup:selectAccount', accountId: a.id });
        render();
      });
      li.appendChild(sw);
    } else if (a.unlocked) {
      li.appendChild(badge('已解锁', 'badge-play'));
    }
    ul.appendChild(li);
  }
  c.appendChild(ul);
  const dim = el('div', { class: 'dim' }, '切换/锁定单账户不影响其他账户（各自密文独立保存）。');
  c.appendChild(dim);
  return c;
}

// ---- 账户主页（解锁态） ----
async function renderAccount(state) {
  const acct = (state.accounts ?? []).find((a) => a.id === state.activeAccountId);

  // 顶部：账户 + 网络
  const c = card(`账户：${acct?.label ?? '默认'}`);
  c.appendChild(row('公钥', shortHex(state.publicKey ?? ''), true));
  const netRow = el('div', { class: 'row' });
  netRow.appendChild(el('span', { class: 'k' }, '网络'));
  const netSel = el('select', { id: 'net-select' });
  for (const id of state.networks ?? []) {
    const opt = el('option', { value: id }, id === state.chainId ? `${id}（当前）` : id);
    if (id === state.chainId) opt.selected = true;
    netSel.appendChild(opt);
  }
  netRow.appendChild(netSel);
  c.appendChild(netRow);
  const confirmNetBtn = el('button', { class: 'secondary' }, '确认切换网络（二次确认）');
  const netErr = errBox();
  confirmNetBtn.addEventListener('click', async () => {
    const target = document.getElementById('net-select').value;
    if (target === state.chainId) { netErr.textContent = '已是当前网络'; return; }
    confirmNetBtn.disabled = true;
    const res = await send({ type: 'popup:switchNetwork', chainId: target });
    confirmNetBtn.disabled = false;
    if (res?.error) { netErr.textContent = `${res.error.code}: ${res.error.reason}`; return; }
    render();
  });
  c.append(confirmNetBtn, netErr);

  // REAL/PLAY 物理分栏余额 + 展示门
  const notesRes = await send({ type: 'popup:getNotes' });
  if (notesRes?.error) {
    $view.appendChild(c);
    const errCard = card('note 视图');
    errCard.appendChild(errBox(`${notesRes.error.code}: ${notesRes.error.reason}`));
    $view.appendChild(errCard);
    return;
  }
  const views = await send({ type: 'popup:getDisplayViews' });
  c.appendChild(renderSplitBalances(notesRes, views));
  $view.appendChild(c);

  // REAL 展示门（wallet-core display.rs 输出；UI 只消费）
  if (views?.real) $view.appendChild(renderRealGate(views.real));

  // REAL 提现预览（0.3，展示态；canSubmit 恒 false——不开放真实提交）
  $view.appendChild(renderWithdrawPreview());

  // 分列 note 列表（脱敏）
  $view.appendChild(renderNoteLists(notesRes));

  // devnet 水龙头（仅 devnet；本地 stub，如实标注）
  if (state.networkKind === 'devnet') $view.appendChild(renderFaucet());

  // 交易回执（inclusion 状态位）
  await renderReceipts();

  // 备份恢复
  $view.appendChild(renderBackupCard());
  $view.appendChild(renderImportCard());

  // proof portal 入口
  $view.appendChild(renderPortalCard(state));

  // 会话密钥（SNIP-12 授权；0.3/0.4）
  await renderSessionKeys();

  // 授权簿（origin 权限管理；0.4 registry）
  await renderRegistry();

  // 钱包能力矩阵（0.4）
  await renderCapabilityMatrix();

  const lockBtn = el('button', { class: 'secondary' }, '锁定当前账户');
  lockBtn.addEventListener('click', async () => { await send({ type: 'popup:lock' }); render(); });
  $view.appendChild(lockBtn);
  $view.appendChild(renderAccountList(state));
  $view.appendChild(renderNewAccountEntry());
}

/** 资产余额分组（TE-M5）：REAL 域三列（NATIVE/USDT/USDC）/ GAME 域组。
 *
 * 0.4 钱包账本为 v1 二元（REAL 只映射 REAL/NATIVE 一列）——USDT/USDC
 * 列如实标注"未接入"（恒空，不伪造 0 值语义）；GAME 域组内已注册 GTS
 * 游戏币列表异步从网关拉取（供给对账口径，非用户余额）。REAL 侧保留
 * 托管警示。 */
function renderSplitBalances(notesRes, views) {
  const g = groupBalances(notesRes.balances ?? {});
  const wrap = el('div', { class: 'split' });

  // REAL 域：三 token 列（封闭枚举）
  const realCol = el('div', { class: 'col real' });
  const realHead = el('h3', {}, 'REAL 域（隔离展示）');
  realHead.appendChild(badge('托管', 'badge-real'));
  realCol.appendChild(realHead);
  const realRows = el('div');
  const mkTokenRow = (label, free, locked, connected) => {
    const r = el('div', { class: 'row' });
    r.appendChild(el('span', { class: 'k' }, `${label} ${connected ? '' : '（未接入）'}`));
    r.appendChild(el('span', { class: connected ? 'v mono' : 'v dim' }, connected ? String(free) : '—'));
    return r;
  };
  realRows.appendChild(mkTokenRow(g.real.native.tokenLabel, g.real.native.free, g.real.native.locked, true));
  realRows.appendChild(mkTokenRow(g.real.usdt.tokenLabel, null, null, false));
  realRows.appendChild(mkTokenRow(g.real.usdc.tokenLabel, null, null, false));
  realCol.appendChild(realRows);
  realCol.appendChild(el('div', { class: 'dim' }, `桌内锁定 NATIVE ${g.real.native.locked}`));
  realCol.appendChild(el('div', { class: 'dim' },
    'USDT/USDC 为 REAL 域 v2 通道（各自独立托管/独立提现，禁跨币轧差）；0.4 钱包账本为 v1，仅 NATIVE 列有值。'));
  if (views?.real?.custody_risk_notice) {
    realCol.appendChild(el('div', { class: 'hint' }, '⚠ REAL 为托管模式（v1）：资产由桌托管账户记账，非自持。'));
  }

  // GAME 域：遗留 PLAY + 已注册 GTS 游戏币（异步）
  const gameCol = el('div', { class: 'col play' });
  const gameHead = el('h3', {}, 'GAME 域（可签名）');
  gameCol.appendChild(gameHead);
  gameCol.appendChild(el('div', { class: 'bal mono' }, `PLAY(legacy) Δ ${g.game.play.free}`));
  gameCol.appendChild(el('div', { class: 'dim' }, `桌内锁定 Δ ${g.game.play.locked}`));
  const registry = el('div', { class: 'game-registry' });
  registry.appendChild(el('div', { class: 'dim' }, '已注册游戏币：获取中…'));
  gameCol.appendChild(registry);

  wrap.append(gameCol, realCol);
  // 异步补全 GAME 域注册币列表（网关不可达/未配置 → 如实标注，不阻塞渲染）
  renderGameTokenRegistry(registry);
  return wrap;
}

/** GAME 域已注册游戏币列表（网关 status.assets；TE-M5）。
 *
 * 展示的是**链上供给对账**：outstanding = Σminted − Σburned（十进制字符
 * 串原样透传，不转数字）；这不是用户余额（0.4 钱包无 GAME v2 note）。
 * consistent:false 的行原样告警（账本 bug 信号，不美化）。 */
async function renderGameTokenRegistry(container) {
  const state = await send({ type: 'popup:getState' });
  const res = await fetchAssetSummary(state.gatewayUrl);
  if (!res.ok) {
    const why = res.code === 'GatewayNotConfigured'
      ? '当前网络未配置网关'
      : res.code === 'BadShape'
        ? '网关无资产摘要（index 模式或旧版网关）'
        : `网关不可达（${res.code}）`;
    container.replaceChildren();
    container.appendChild(el('div', { class: 'dim' }, `已注册游戏币：未获取（${why}）。`));
    return;
  }
  const s = summarizeGatewayAssets(res.assets);
  container.replaceChildren();
  if (!s.ok) {
    container.appendChild(el('div', { class: 'dim' }, `已注册游戏币：未获取（${s.code}）。`));
    return;
  }
  const gts = s.gameTokens.filter((t) => !t.legacy);
  if (gts.length === 0) {
    container.appendChild(el('div', { class: 'dim' }, '已注册游戏币：无（链上注册表为空）。'));
    return;
  }
  for (const t of gts) {
    const box = el('div', { class: 'receipt' });
    const head = el('div');
    head.appendChild(badge(t.label, 'badge-play'));
    head.appendChild(el('span', { class: 'dim' }, ` · token_id ${t.tokenId} · ${t.registered ? '已注册' : '未注册'} · mode ${t.mode ?? '—'}`));
    box.appendChild(head);
    box.appendChild(row('供给 outstanding（Σminted − Σburned）', t.outstanding ?? '—', true));
    if (t.anchor) box.appendChild(row('锚定资产', t.anchor, true));
    if (t.rate) box.appendChild(row('发行比率 R（每 1e18 wei）', t.rate, true));
    if (t.maxSupply) box.appendChild(row('供给上限', t.maxSupply === '0' ? '不限' : t.maxSupply, true));
    if (!t.consistent) box.appendChild(el('div', { class: 'hint' }, '⚠ 供给恒等式核对不一致（outstanding ≠ 存续 note 合计）——如实告警。'));
    container.appendChild(box);
  }
  container.appendChild(el('div', { class: 'dim' },
    'GAME 币为游戏内虚拟筹码：单向获取（购买/赠送入口），不可赎回、不可与 REAL 域资产兑换、不可跨链（结构性质）；供给数字为链上对账口径，非用户余额，不构成任何价值承诺。'));
}

/** REAL 展示门卡片：claim 恒隐藏（0.2 全链路未就绪）+ finality 状态说明。 */
function renderRealGate(realView) {
  const c = card('REAL 操作面');
  if (realView.show_claim) {
    // 不可达路径（0.2 readiness 恒 offline；wallet-core 就绪才允许）。
    c.appendChild(el('div', { class: 'ok-box' }, 'claim 操作（就绪态）'));
  } else {
    c.appendChild(row('claim 操作', '未开放（不暗示可提现）'));
    c.appendChild(row('原因', realView.claim_disabled_reason ?? '', true));
    const notice = el('div', { class: 'warn-box' },
      'REAL 为托管模式（v1）：余额是托管记账的凭证，提现/出入金通道未上线。' +
      'finality 状态以 note 的 proof 层级展示（pending/soft/proven/finalized），' +
      '本页面不对 REAL 提供任何转账或兑换操作。');
    c.appendChild(notice);
  }
  return c;
}

/** REAL/GAME 域分列 note 列表（脱敏；无 spend secret/nullifier）。
 * TE-M5：每张 note 带资产徽章（v1 账本经冻结映射升维展示）。 */
function renderNoteLists(notesRes) {
  const wrap = el('div', { class: 'split' });
  const mk = (title, items, cls, emptyText, domain) => {
    const col = el('div', { class: `col ${cls}` });
    const head = el('h3', {}, title);
    head.appendChild(badge(domain, domain === 'REAL' ? 'badge-real' : 'badge-play'));
    col.appendChild(head);
    const ul = el('ul', { class: 'notes' });
    if (!items || items.length === 0) {
      ul.appendChild(el('li', { class: 'dim' }, emptyText));
    }
    for (const n of items) {
      const li = el('li');
      const b = assetBadge(domain);
      li.appendChild(badge(b.ok ? b.tokenLabel : domain, b.ok ? b.badgeClass : 'badge-real'));
      li.appendChild(el('span', { class: 'mono' }, ` ${n.amount}`));
      const right = el('span');
      right.appendChild(el('span', { class: 'proof' }, `${n.proof} · ${n.spendable ? '可用' : '锁定'} · `));
      right.appendChild(el('span', { class: 'mono' }, shortHex(n.commitment, 8, 4)));
      li.appendChild(right);
      ul.appendChild(li);
    }
    col.appendChild(ul);
    return col;
  };
  wrap.append(
    mk('note（脱敏）', notesRes.notes, 'play', '暂无 note（devnet 水龙头铸造测试 PLAY）', 'GAME'),
    mk('REAL note（脱敏）', notesRes.realNotes, 'real', '暂无 REAL note（0.2 不开放 REAL 入金/铸造）', 'REAL'),
  );
  return wrap;
}

function renderFaucet() {
  const faucet = card('devnet 水龙头（本地 stub，仅测试）');
  const amount = el('input', { type: 'number', id: 'faucet-amount', min: '1', placeholder: '金额（如 100）' });
  const err = errBox();
  const fbtn = el('button', { class: 'secondary' }, '铸造 PLAY note');
  fbtn.addEventListener('click', async () => {
    const v = Number(amount.value);
    if (!Number.isSafeInteger(v) || v <= 0) { err.textContent = '金额必须是正整数'; return; }
    const res = await send({ type: 'popup:faucet', amount: v });
    if (res?.error) { err.textContent = `${res.error.code}: ${res.error.reason}`; return; }
    render();
  });
  faucet.append(amount, err, fbtn);
  return faucet;
}

// ---- 交易回执（inclusion 状态位；ForceInclude 仅展示） ----
async function renderReceipts() {
  const { receipts } = await send({ type: 'popup:receipts' });
  const c = card('交易回执（inclusion 状态）');
  if (!receipts || receipts.length === 0) {
    c.appendChild(el('div', { class: 'dim' }, '暂无回执（签名成功后登记）。'));
    $view.appendChild(c);
    return;
  }
  for (const r of receipts.slice(0, 8)) {
    const box = el('div', { class: 'receipt' });
    const head = el('div');
    head.appendChild(el('span', { class: `st ${r.status}` }, inclusionLabel(r)));
    head.appendChild(el('span', { class: 'dim' }, ` · ${r.kind} · ${r.chainId ?? ''}`));
    box.appendChild(head);
    box.appendChild(el('div', { class: 'mono dim' }, shortHex(r.digest, 12, 8)));
    if (r.view?.hint) box.appendChild(el('div', { class: 'hint' }, r.view.hint));

    const detail = el('details');
    const summary = el('summary', {}, '导入 SeenReceipt / 登记 included');
    detail.appendChild(summary);
    const ta = el('input', { type: 'text', placeholder: 'SeenReceipt JSON（chain_id/tx_hash/seen_at_ms/validator_pubkey/signature）' });
    const err = errBox();
    const seenBtn = el('button', { class: 'secondary' }, '标记 seen（回执未验签，如实标注）');
    seenBtn.addEventListener('click', async () => {
      let receipt = null;
      try { receipt = JSON.parse(ta.value); } catch { err.textContent = 'JSON 解析失败'; return; }
      const res = await send({ type: 'popup:receiptSeen', digest: r.digest, receipt });
      if (res?.error) { err.textContent = `${res.error.code}: ${res.error.reason}`; return; }
      render();
    });
    const incBtn = el('button', { class: 'secondary' }, '人工登记 included（非链上证实）');
    incBtn.addEventListener('click', async () => {
      const res = await send({ type: 'popup:receiptIncluded', digest: r.digest });
      if (res?.error) { err.textContent = `${res.error.code}: ${res.error.reason}`; return; }
      render();
    });
    detail.append(ta, err, seenBtn, incBtn);
    box.appendChild(detail);
    c.appendChild(box);
  }
  $view.appendChild(c);
}

function inclusionLabel(r) {
  if (r.status === 'included') return 'included（已包含）';
  if (r.status === 'seen') return r.view?.pastDeadline ? 'seen（已超 deadline）' : 'seen（已见证）';
  return r.view?.pastDeadline ? 'signed（已超 deadline）' : 'signed（等待见证）';
}

// ---- 备份导出 ----
function renderBackupCard() {
  const c = card('加密备份导出');
  c.appendChild(el('div', { class: 'dim' },
    'wallet-core ZCBK v1：REAL/PLAY 双库 + keystore 信封 + 声明索引自检，口令加密（Argon2id + ChaCha20-Poly1305）。'));
  const p = el('input', { type: 'password', placeholder: '备份口令（≥ 8 字符，可与钱包口令不同）' });
  const err = errBox();
  const btn = el('button', {}, '导出备份文件（.zcbk）');
  btn.addEventListener('click', async () => {
    if (p.value.length < 8) { err.textContent = '口令太短（≥ 8 字符）'; return; }
    btn.disabled = true;
    const res = await send({ type: 'popup:backupExport', password: p.value });
    btn.disabled = false;
    p.value = '';
    if (res?.error) { err.textContent = `${res.error.code}: ${res.error.reason}`; return; }
    // hex → 二进制文件下载（文件字节 = wallet-core EncryptedBackup borsh）。
    const bytes = new Uint8Array(res.backupHex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(res.backupHex.slice(i * 2, i * 2 + 2), 16);
    const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
    const a = el('a', { href: url, download: `zchain-backup-${res.createdUnix ?? Date.now()}.zcbk` });
    a.click();
    URL.revokeObjectURL(url);
    err.textContent = '';
    c.appendChild(el('div', { class: 'ok-box' }, `备份已导出（REAL ${res.notes?.real ?? 0} + PLAY ${res.notes?.play ?? 0} notes）。请离线保存口令与文件。`));
  });
  c.append(p, err, btn);
  return c;
}

// ---- 备份导入（fail-closed） ----
function renderImportCard() {
  const c = card('从备份恢复（导入）');
  c.appendChild(el('div', { class: 'dim' },
    '导入 = 校验（结构/魔数/版本 → 口令 AEAD → 索引自检）→ 新增一个**锁定**账户。错误口令或篡改文件一律拒绝（fail-closed）。'));
  const file = el('input', { type: 'file', id: 'backup-file' });
  if (!file.style) { /* noop */ }
  file.style.marginBottom = '8px';
  const p = el('input', { type: 'password', placeholder: '备份口令' });
  const err = errBox();
  const btn = el('button', {}, '校验并恢复为新账户');
  btn.addEventListener('click', async () => {
    const f = file.files?.[0];
    if (!f) { err.textContent = '请选择 .zcbk 备份文件'; return; }
    btn.disabled = true;
    try {
      const buf = new Uint8Array(await f.arrayBuffer());
      let hex = '';
      for (const b of buf) hex += b.toString(16).padStart(2, '0');
      const res = await send({ type: 'popup:backupImport', backupHex: hex, password: p.value });
      if (res?.error) {
        const human = {
          BadPassword: '口令错误（AEAD 认证失败）',
          Tampered: '备份已篡改或结构非法（fail-closed）',
          UnsupportedVersion: '备份版本不受支持（只升不降）',
        }[res.error.code];
        err.textContent = human ?? `${res.error.code}: ${res.error.reason}`;
        return;
      }
      p.value = '';
      file.value = '';
      c.appendChild(el('div', { class: 'ok-box' },
        `恢复完成：新增锁定账户（索引 ${res.indexes?.commitments ?? 0} commitments / ${res.indexes?.nullifiers ?? 0} nullifiers）。用备份口令解锁该账户即可使用。`));
      render();
    } finally {
      btn.disabled = false;
    }
  });
  c.append(file, p, err, btn);
  return c;
}

// ---- proof portal 入口 ----
function renderPortalCard(state) {
  const c = card('Proof Portal（验证一手牌）');
  c.appendChild(el('div', { class: 'dim' },
    `hand binding → 网关结算明细（payout_root / rake / 层级）→ proof 归档 → wallet-core 本地复验。当前网络 ${state.chainId}，网关 ${state.gatewayUrl ?? '未配置'}。`));
  const btn = el('button', {}, '打开 Proof Portal');
  btn.addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('portal/portal.html') });
  });
  c.appendChild(btn);
  return c;
}

// ---------------------------------------------------------------------------
// Extension 0.3：REAL 提现预览（展示态；不开放真实提交）
// ---------------------------------------------------------------------------

function renderWithdrawPreview() {
  const c = card('REAL 提现预览（仅展示）');
  c.appendChild(el('div', { class: 'dim' },
    'REAL 为托管模式（v1）：本页面只做逐字段预览（金额/收款 owner/finality/托管风险），不开放真实提现提交。finality 未达 finalized 恒禁用。'));
  const amount = el('input', { type: 'text', placeholder: '金额（REAL，十进制）' });
  const owner = el('input', { type: 'text', placeholder: '收款 owner（66 位 hex）' });
  const err = errBox();
  const out = el('div');
  const btn = el('button', { class: 'secondary' }, '生成预览');
  btn.addEventListener('click', async () => {
    out.replaceChildren();
    err.textContent = '';
    const res = await send({ type: 'popup:withdrawPreview', amount: amount.value.trim(), owner: owner.value.trim() });
    if (res?.error) { err.textContent = `${res.error.code}: ${res.error.reason}`; return; }
    const p = res.preview;
    out.appendChild(row('asset_class', 'REAL（托管）'));
    out.appendChild(row('kind', p.kind));
    out.appendChild(row('金额', p.amount, true));
    out.appendChild(row('收款 owner', shortHex(p.owner, 14, 8), true));
    out.appendChild(row('finality', `${p.finality.worstProof}（要求 ${p.finality.requiredProof}）`));
    for (const [i, n] of (p.inputs ?? []).entries()) {
      out.appendChild(row(`输入#${i}`, `${n.amount} · ${n.proof} · ${shortHex(n.commitment ?? '', 6, 4)}`, true));
    }
    for (const r of p.cannotSubmitReasons ?? []) {
      out.appendChild(el('div', { class: 'hint' }, `⛔ ${r}`));
    }
    const submit = el('button', { class: 'approve', disabled: '' }, '提交提现（未开放）');
    submit.disabled = true;
    submit.addEventListener('click', () => { /* 永不触达：display-only 红线 */ });
    out.appendChild(el('div', { class: 'dim' }, '提交按钮保持禁用：提现提交路径随 Vault 上线单独交付，本版本不实现。'));
    out.appendChild(submit);
  });
  c.append(amount, owner, err, btn, out);
  return c;
}

// ---------------------------------------------------------------------------
// Extension 0.3/0.4：会话密钥（SNIP-12 授权：创建 → 摘要确认 → 登记 → 撤销）
// ---------------------------------------------------------------------------

const SESSION_STATUS_LABEL = {
  active: '生效中',
  exhausted: '日限已用尽',
  revoked: '已撤销（粘滞）',
  expired: '已过期（自然失效）',
  not_yet_valid: '未生效',
  unknown: '未知',
};

async function renderSessionKeys() {
  const reg = await send({ type: 'popup:getRegistry' });
  const c = card('会话密钥（SNIP-12 授权）');
  c.appendChild(el('div', { class: 'dim' },
    'delegated key 由 wallet-core 生成（私钥只活在 wasm 会话，锁定即毁）；授权约束登记在本授权簿。撤销为粘滞：撤销后该 origin 的签名请求一律拒绝。'));

  const list = reg.sessionKeys ?? [];
  if (list.length === 0) c.appendChild(el('div', { class: 'dim' }, '暂无会话密钥授权。'));
  for (const b of list) {
    const box = el('div', { class: 'receipt' });
    const head = el('div');
    head.appendChild(el('span', { class: `st ${b.status === 'active' ? 'included' : b.status === 'revoked' ? 'seen' : ''}` }, SESSION_STATUS_LABEL[b.status] ?? b.status));
    head.appendChild(el('span', { class: 'dim' }, ` · ${b.origin} · ${b.chainId}`));
    box.appendChild(head);
    box.appendChild(row('scope', b.allowedScopes.join(', '), true));
    box.appendChild(row('单笔/每日限额', `${b.perTxLimit ?? '不限'} / ${b.perDayLimit ?? '不限'}（今日已用 ${b.dailyUsedToday}）`, true));
    box.appendChild(row('桌白名单', b.tableAllowlist == null ? '全部桌' : b.tableAllowlist.join(', '), true));
    box.appendChild(row('有效期', `${b.validAfter} → ${b.validUntil}（unix 秒）`, true));
    box.appendChild(row('binding', shortHex(b.bindingId, 8, 6), true));
    box.appendChild(el('div', { class: 'hint' }, `登记来源：${b.evidence}（链侧 admission 登记未接）`));
    const btns = el('div', { class: 'btn-row' });
    if (!b.revoked) {
      const rev = el('button', { class: 'reject' }, '撤销');
      rev.addEventListener('click', async () => {
        rev.disabled = true;
        await send({ type: 'popup:sessionRevoke', bindingId: b.bindingId });
        render();
      });
      btns.appendChild(rev);
    }
    const del = el('button', { class: 'secondary' }, '删除记录');
    del.addEventListener('click', async () => {
      del.disabled = true;
      await send({ type: 'popup:sessionDelete', bindingId: b.bindingId });
      render();
    });
    btns.appendChild(del);
    box.appendChild(btns);
    c.appendChild(box);
  }

  // ---- 创建授权（devnet 入口形态）----
  const detail = el('details');
  detail.appendChild(el('summary', {}, '创建授权（devnet 入口形态）'));
  const origin = el('input', { type: 'text', placeholder: '授权面向的站点 origin（如 http://localhost:8080）' });
  const addr = el('input', { type: 'text', placeholder: '授权方账户地址（Starknet felt hex，devnet 入口形态手输）' });
  const scopeWrap = el('div');
  scopeWrap.appendChild(el('div', { class: 'dim' }, 'scope（默认只勾 PLAY 与低风险牌局操作；withdraw 永不可选）'));
  const scopeBoxes = {};
  for (const s of ['play', 'buyin', 'bet', 'settle', 'transfer', 'withdraw']) {
    const id = `scope-${s}`;
    const cb = el('input', { type: 'checkbox', id, value: s });
    cb.style.width = 'auto';
    cb.checked = ['play', 'buyin', 'bet', 'settle'].includes(s);
    if (s === 'withdraw') { cb.checked = false; cb.disabled = true; }
    const label = el('label', { for: id }, s);
    label.style.display = 'inline-flex';
    label.style.alignItems = 'center';
    label.style.gap = '4px';
    label.style.marginRight = '10px';
    const wrap = el('span');
    wrap.style.display = 'inline-flex';
    wrap.appendChild(cb);
    wrap.appendChild(label);
    scopeWrap.appendChild(wrap);
    scopeBoxes[s] = cb;
  }
  const perTx = el('input', { type: 'text', placeholder: '单笔限额（十进制，留空 = 不限）' });
  const perDay = el('input', { type: 'text', placeholder: '每日限额（十进制，留空 = 不限）' });
  const tables = el('input', { type: 'text', placeholder: '桌白名单（逗号分隔，留空 = 全部桌）' });
  const validity = el('input', { type: 'text', placeholder: '有效期（小时，默认 24）' });
  const err = errBox();
  const draftOut = el('div');
  const genBtn = el('button', {}, '生成授权（wallet-core 生成 delegated key + SNIP-12 摘要）');
  genBtn.addEventListener('click', async () => {
    draftOut.replaceChildren();
    err.textContent = '';
    const allowedScopes = Object.entries(scopeBoxes).filter(([, cb]) => cb.checked).map(([s]) => s);
    const res = await send({
      type: 'popup:sessionDraft',
      origin: origin.value.trim(),
      accountAddress: addr.value.trim(),
      allowedScopes,
      perTxLimit: perTx.value.trim() || null,
      perDayLimit: perDay.value.trim() || null,
      tableAllowlist: tables.value,
      validitySec: validity.value.trim() ? Number(validity.value.trim()) * 3600 : null,
    });
    if (res?.error) { err.textContent = `${res.error.code}: ${res.error.reason}`; return; }
    renderDraftSummary(draftOut, res);
  });
  detail.append(origin, addr, scopeWrap, perTx, perDay, tables, validity, err, genBtn, draftOut);
  c.appendChild(detail);
  $view.appendChild(c);
}

/** SNIP-12 授权摘要确认卡（逐字段 + wallet-core 摘要；确认才登记）。 */
function renderDraftSummary(container, res) {
  const box = el('div', { class: 'receipt' });
  box.appendChild(el('div', { class: 'st' }, 'SNIP-12 AuthorizeZChainKey（确认后登记）'));
  box.appendChild(row('origin', res.origin, true));
  box.appendChild(row('chain_id', res.request.chainId, true));
  box.appendChild(row('account_address', shortHex(res.request.accountAddress, 12, 8), true));
  box.appendChild(row('delegated_public_key', shortHex(res.key.delegated_public_key, 12, 8), true));
  box.appendChild(row('allowed_scopes', res.request.allowedScopes.join(', '), true));
  box.appendChild(row('单笔/每日限额', `${res.request.perTxLimit ?? '不限'} / ${res.request.perDayLimit ?? '不限'}`, true));
  box.appendChild(row('桌白名单', res.request.tableAllowlist == null ? '全部桌' : res.request.tableAllowlist.join(', '), true));
  box.appendChild(row('有效期', `${res.request.validAfter} → ${res.request.validUntil}`, true));
  box.appendChild(row('nonce', String(res.request.nonce), true));
  box.appendChild(row('SNIP-12 摘要（wallet-core）', shortHex(res.digest, 14, 10), true));
  box.appendChild(el('div', { class: 'warn-box' },
    '请逐字段核对上方摘要。登记即把约束写入授权簿（devnet 入口形态：本地登记，链侧 admission 登记未接——evidence 如实标注）。'));

  const btns = el('div', { class: 'btn-row' });
  const ok = el('button', { class: 'approve' }, '确认登记');
  const no = el('button', { class: 'secondary' }, '取消');
  ok.addEventListener('click', async () => {
    ok.disabled = no.disabled = true;
    const r = await send({
      type: 'popup:sessionRegister',
      origin: res.origin,
      binding: {
        bindingId: res.key.binding_id,
        delegatedPublicKey: res.key.delegated_public_key,
        chainId: res.request.chainId,
        accountAddress: res.request.accountAddress,
        allowedScopes: res.request.allowedScopes,
        perTxLimit: res.request.perTxLimit,
        perDayLimit: res.request.perDayLimit,
        tableAllowlist: res.request.tableAllowlist,
        nonce: res.request.nonce,
        validAfter: res.request.validAfter,
        validUntil: res.request.validUntil,
        digest: res.digest,
      },
    });
    if (r?.error) { box.appendChild(errBox(`${r.error.code}: ${r.error.reason}`)); ok.disabled = no.disabled = false; return; }
    render();
  });
  no.addEventListener('click', () => container.replaceChildren());
  btns.append(ok, no);
  box.appendChild(btns);
  container.appendChild(box);
}

// ---------------------------------------------------------------------------
// Extension 0.4：授权簿（origin 权限管理）
// ---------------------------------------------------------------------------

async function renderRegistry() {
  const reg = await send({ type: 'popup:getRegistry' });
  const c = card('授权簿（origin 权限 · 当前账户）');
  const origins = reg.origins ?? [];
  if (origins.length === 0) {
    c.appendChild(el('div', { class: 'dim' }, '无已授权站点。'));
  }
  for (const o of origins) {
    const box = el('div', { class: 'receipt' });
    box.appendChild(row('origin', o.origin, true));
    box.appendChild(row('授权时间', o.grantedAt != null ? new Date(o.grantedAt).toISOString() : '（0.1 迁移）'));
    const btns = el('div', { class: 'btn-row' });
    const rev = el('button', { class: 'reject' }, '撤销');
    rev.addEventListener('click', async () => {
      rev.disabled = true;
      const r = await send({ type: 'popup:revokeOrigin', origin: o.origin });
      if (r?.error) box.appendChild(errBox(`${r.error.code}: ${r.error.reason}`));
      render();
    });
    btns.appendChild(rev);
    box.appendChild(btns);
    c.appendChild(box);
  }
  c.appendChild(el('div', { class: 'dim' },
    '权限/网络/账户按 origin 与账户隔离保存；撤销后该站点所有请求将被 OriginNotPermitted 拒绝（可再次连接重新授权）。'));
  $view.appendChild(c);
}

// ---------------------------------------------------------------------------
// Extension 0.4：钱包能力矩阵
// ---------------------------------------------------------------------------

async function renderCapabilityMatrix() {
  const res = await send({ type: 'popup:capabilityMatrix' });
  const m = res?.matrix;
  const c = card('钱包能力矩阵');
  if (!m) {
    c.appendChild(el('div', { class: 'dim' }, '能力矩阵不可用。'));
    $view.appendChild(c);
    return;
  }
  c.appendChild(row('本钱包 provider', `v${m.own.providerVersion ?? ''} · ${m.own.currentNetwork ?? ''}`, true));
  const detail = el('details');
  detail.appendChild(el('summary', {}, '外部钱包/客户端能力（EIP-1193 / WalletConnect / Starknet）'));
  for (const r of m.rows) {
    const box = el('div', { class: 'receipt' });
    const head = el('div');
    head.appendChild(el('span', { class: 'st' }, r.protocol));
    head.appendChild(el('span', { class: 'dim' }, r.active ? ' · 启用' : ' · 未激活'));
    box.appendChild(head);
    box.appendChild(el('div', { class: 'dim' }, r.summary));
    if ((r.supported ?? []).length > 0) {
      const ul = el('ul', { class: 'notes' });
      for (const s of r.supported) {
        const li = el('li');
        li.appendChild(el('span', { class: 'mono' }, s.name));
        li.appendChild(el('span', { class: 'proof' }, s.detail));
        ul.appendChild(li);
      }
      box.appendChild(ul);
    }
    for (const d of r.denied ?? []) {
      box.appendChild(el('div', { class: 'hint' }, `⛔ ${d.name}：${d.reason}`));
    }
    detail.appendChild(box);
  }
  c.appendChild(detail);
  $view.appendChild(c);
}

// ---- 待签名/连接/换网请求（结构化预览确认页）----
async function renderPending() {
  const { pending } = await send({ type: 'popup:listPending' });
  if (!pending || pending.length === 0) return;

  for (const p of pending) {
    if (p.kind === 'connect') {
      const c = card('连接请求');
      c.appendChild(row('来源 origin', p.origin, true));
      c.appendChild(row('request_id', p.requestId, true));
      c.appendChild(row('method', p.method, true));
      c.appendChild(el('div', { class: 'warn-box' },
        '该站点请求连接并读取你的公钥与 PLAY 余额状态。批准即写入**当前账户**的授权（账户隔离；可随时在授权列表审查）。'));
      appendDecideButtons(c, p.requestId);
      $view.appendChild(c);
      continue;
    }

    if (p.kind === 'switch_network') {
      const c = card('网络切换请求（二次确认）');
      const pv = p.preview ?? {};
      c.appendChild(row('来源 origin', p.origin, true));
      c.appendChild(row('当前网络', `${pv.fromChainId}（${pv.fromKind}）`, true));
      c.appendChild(row('目标网络', `${pv.toChainId}（${pv.toKind}）`, true));
      c.appendChild(el('div', { class: 'warn-box' },
        '切换后：签名请求的 chain_id 必须与目标网络一致（chain_id 参与签名摘要域，跨网重放必换摘要）；网关/explorer 地址按目标网络解析。devnet/testnet 之外的网络（含 mainnet）不在注册表内，一律拒绝。'));
      appendDecideButtons(c, p.requestId);
      $view.appendChild(c);
      continue;
    }

    const c = card('签名请求');
    c.appendChild(row('来源 origin', p.origin, true));
    c.appendChild(row('request_id', p.requestId, true));
    c.appendChild(row('method', p.method, true));

    const pv = p.preview ?? {};
    // TE-M5：资产徽章（v1 asset_class 经冻结映射升维展示 REAL/NATIVE、
    // GAME/PLAY(legacy)——签名面资产语义与余额分组同一解析表）
    const ab = assetBadge(pv.asset_class ?? 'PLAY');
    const assetRow = el('div', { class: 'row' });
    assetRow.appendChild(el('span', { class: 'k' }, 'asset'));
    assetRow.appendChild(badge(ab.ok ? `${ab.domainName}/${ab.tokenLabel}` : String(pv.asset_class ?? 'PLAY'), ab.ok ? ab.badgeClass : 'badge-real'));
    c.appendChild(assetRow);

    c.appendChild(row('kind', pv.kind ?? ''));
    c.appendChild(row('chain_id', pv.chain_id ?? '', true));
    c.appendChild(row('domain / ABI', `${pv.domain ?? ''} / v${pv.abi_version ?? ''}`, true));
    c.appendChild(row('amount_in', pv.amount_in ?? ''));
    c.appendChild(row('amount_out', pv.amount_out ?? ''));
    c.appendChild(row('rake', pv.rake ?? '0'));
    if (pv.table_id != null) c.appendChild(row('table_id', pv.table_id));
    for (const [i, o] of (pv.outputs ?? []).entries()) {
      c.appendChild(row(`输出#${i} → owner`, `${o.amount} → ${shortHex(o.owner, 12, 8)}`, true));
    }
    if (pv.request_id) c.appendChild(row('request_id（操作）', shortHex(pv.request_id, 10, 6), true));
    if (pv.hand_binding) c.appendChild(row('hand_binding', shortHex(pv.hand_binding, 10, 6), true));
    (pv.proof_states ?? []).forEach((s, i) => c.appendChild(row(`proof[${i}]`, s)));
    c.appendChild(row('nonce', pv.nonce ?? ''));
    c.appendChild(row('过期 (unix)', pv.expiry ?? ''));
    c.appendChild(row('确认摘要', shortHex(pv.digest ?? '', 12, 8), true));

    c.appendChild(el('div', { class: 'warn-box' },
      '签名前请逐字段核对：以上展示即签名内容（预览摘要绑定）。任何字段与预期不符请拒绝。'));
    appendDecideButtons(c, p.requestId);
    $view.appendChild(c);
  }
}

function appendDecideButtons(container, requestId) {
  const rowEl = el('div', { class: 'btn-row' });
  const ok = el('button', { class: 'approve' }, '批准');
  const no = el('button', { class: 'reject' }, '拒绝');
  ok.addEventListener('click', async () => {
    ok.disabled = no.disabled = true;
    await send({ type: 'popup:approve', requestId });
    render();
  });
  no.addEventListener('click', async () => {
    ok.disabled = no.disabled = true;
    await send({ type: 'popup:reject', requestId });
    render();
  });
  rowEl.append(ok, no);
  container.appendChild(rowEl);
}

render();
