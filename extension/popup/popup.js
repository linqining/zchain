// =============================================================================
// extension/popup/popup.js — 最小 UI：解锁 / 账户 / 待签名请求的结构化预览确认
//
// 预览字段严格对齐 plan-appchain §6.12.4 / wallet-core SigningPreview：
// chain_id、table_id、asset_class、输入/输出金额、收款 owner、rake、
// hand_binding、request_id、proof 状态、过期、nonce、确认摘要（digest）。
// REAL/PLAY 徽章区分；PLAY 默认。0.1 只有 PLAY；REAL 徽章仅供 0.2 复用。
//
// 日志纪律（WALLET-ACC-4）：本文件不使用 console 输出任何请求内容；
// 密码只存在于表单值并直接传给后台，不落 storage、不入日志。
// =============================================================================

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

// ---------------------------------------------------------------------------
// 渲染
// ---------------------------------------------------------------------------

async function render() {
  const state = await send({ type: 'popup:getState' });
  $net.textContent = `${state.networkKind} · ${state.chainId}`;
  $view.replaceChildren();

  if (!state.hasKeystore) return renderCreate();
  if (!state.unlocked) return renderUnlock();
  await renderAccount(state);
  await renderPending();
}

// ---- 创建钱包 ----
function renderCreate() {
  const c = card('创建钱包（本地 keystore）');
  const warn = el('div', { class: 'warn-box' },
    'Extension 0.1 仅 PLAY/devnet。口令用于 Argon2id 派生 KEK 加密 owner key 与 DEK（wallet-core）；口令丢失无法恢复。');
  c.appendChild(warn);
  const p1 = el('input', { type: 'password', id: 'pw', placeholder: '口令（≥ 8 字符）' });
  const p2 = el('input', { type: 'password', id: 'pw2', placeholder: '重复口令' });
  const err = errBox();
  const btn = el('button', {}, '创建（真实 Argon2id + secp256k1）');
  btn.addEventListener('click', async () => {
    if (p1.value.length < 8) { err.textContent = '口令太短（≥ 8 字符）'; return; }
    if (p1.value !== p2.value) { err.textContent = '两次口令不一致'; return; }
    btn.disabled = true;
    const res = await send({ type: 'popup:create', password: p1.value });
    if (res?.error) { err.textContent = `${res.error.code}: ${res.error.reason}`; btn.disabled = false; return; }
    p1.value = ''; p2.value = '';
    render();
  });
  c.append(p1, p2, err, btn);
  $view.appendChild(c);
}

// ---- 解锁 ----
function renderUnlock() {
  const c = card('解锁');
  const p = el('input', { type: 'password', id: 'pw', placeholder: '口令' });
  const err = errBox();
  const btn = el('button', {}, '解锁');
  btn.addEventListener('click', async () => {
    btn.disabled = true;
    const res = await send({ type: 'popup:unlock', password: p.value });
    btn.disabled = false;
    p.value = ''; // 口令不驻留 DOM
    if (res?.error) { err.textContent = res.error.code === 'BadPassword' ? '口令错误（fail-closed）' : `${res.error.code}: ${res.error.reason}`; return; }
    render();
  });
  c.append(p, err, btn);
  $view.appendChild(c);
}

// ---- 账户 ----
async function renderAccount(state) {
  const c = card('账户');
  const badgeWrap = el('div', { class: 'row' });
  badgeWrap.appendChild(el('span', { class: 'k' }, '资产'));
  badgeWrap.appendChild(el('span', { class: 'badge badge-play' }, 'PLAY'));
  c.appendChild(badgeWrap);
  c.appendChild(row('公钥', shortHex(state.publicKey ?? ''), true));
  const notes = await send({ type: 'popup:getNotes' });
  const list = card('PLAY note（脱敏）');
  const ul = el('ul', { class: 'notes' });
  const items = notes?.notes ?? [];
  if (items.length === 0) {
    ul.appendChild(el('li', { class: 'dim' }, '暂无 note（用下方 devnet 水龙头铸造测试 PLAY）'));
  }
  for (const n of items) {
    const li = el('li');
    li.appendChild(el('span', { class: 'mono' }, `Δ ${n.amount}`));
    const right = el('span');
    right.appendChild(el('span', { class: 'proof' }, `${n.proof} · ${n.spendable ? '可用' : '锁定'} · `));
    right.appendChild(el('span', { class: 'mono' }, shortHex(n.commitment, 8, 4)));
    li.appendChild(right);
    ul.appendChild(li);
  }
  list.appendChild(ul);

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

  const lockBtn = el('button', { class: 'secondary' }, '锁定钱包');
  lockBtn.addEventListener('click', async () => { await send({ type: 'popup:lock' }); render(); });

  const origins = card('已授权站点');
  if ((state.grantedOrigins ?? []).length === 0) {
    origins.appendChild(el('div', { class: 'dim' }, '无'));
  }
  for (const o of state.grantedOrigins ?? []) {
    origins.appendChild(row('origin', o, true));
  }

  $view.append(c, list, faucet, origins, lockBtn);
}

// ---- 待签名/连接请求（结构化预览确认页）----
async function renderPending() {
  const { pending } = await send({ type: 'popup:listPending' });
  if (!pending || pending.length === 0) return;

  for (const p of pending) {
    const c = card(p.kind === 'connect' ? '连接请求' : '签名请求');
    c.appendChild(row('来源 origin', p.origin, true));
    c.appendChild(row('request_id', p.requestId, true));
    c.appendChild(row('method', p.method, true));

    if (p.kind === 'connect') {
      c.appendChild(el('div', { class: 'warn-box' },
        '该站点请求连接并读取你的公钥与 PLAY 余额状态。批准即写入该 origin 的授权（可随时在下方授权列表审查）。'));
      appendDecideButtons(c, p.requestId);
      $view.appendChild(c);
      continue;
    }

    const pv = p.preview ?? {};
    const asset = pv.asset_class ?? 'PLAY';
    const badge = el('span', { class: asset === 'REAL' ? 'badge badge-real' : 'badge badge-play' }, asset);
    const assetRow = el('div', { class: 'row' });
    assetRow.appendChild(el('span', { class: 'k' }, 'asset_class'));
    assetRow.appendChild(badge);
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
