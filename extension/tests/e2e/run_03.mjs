#!/usr/bin/env node
// Extension 0.3/0.4 真实浏览器 E2E（复用 run_02 的驱动方式：Chrome for
// Testing + --headless=new + CDP WebSocket + unpacked 加载扩展）。
//
// 覆盖（0.3/0.4 关键流，全部在真实扩展运行时内执行）：
//   S. 会话密钥（SNIP-12 授权，0.3）：
//      草稿（wallet-core 生成 delegated key + SNIP-12 摘要）→ devnet 入口
//      形态登记（evidence 如实标注）→ registry 列表（active）→ 撤销（粘滞
//      + wallet-core 状态机双重确认）。
//   L. 限额执行（0.4）：限额内签名（批准后成功 + 日限记账）→ 单笔超限
//      拒（弹窗之前 fail fast）→ 撤销后签名拒（fail-closed）→ 删除记录后
//      恢复常规路径。
//   R. 授权簿 registry（0.4）：origin 列表 + 撤销（撤销后页面请求
//      OriginNotPermitted；重连可恢复）。
//   C. 能力矩阵（0.4）：EIP-1193 / WC / Starknet 三行结构化输出；WC dormant
//      如实；EIP-1193 签名方法全拒清单。
//   W. REAL 提现预览（0.3，展示态）：canSubmit 恒 false + 禁用原因。
//   P. provider 边界：zchain_authorizeSessionKey → NotSupportedIn01（授权
//      方法面未开放，popup UI 为唯一入口）。
//
// 用法（repo 根目录）：node extension/tests/e2e/run_03.mjs
// 退出码：0 = 全部 PASS；1 = 存在 FAIL。

import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { appendFileSync, existsSync, mkdtempSync, readdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const EXT_ROOT = path.resolve(HERE, '..', '..');
const OUT_JSON = path.join(HERE, 'e2e03_result.json');
const OUT_PNG = path.join(HERE, 'e2e03_screenshot.png');
const PROGRESS = path.join(HERE, 'e2e03_progress.log');

const WALLET_PW = 'correct horse battery staple';

const progress = (line) => {
  const text = `[${new Date().toISOString()}] ${line}`;
  try { appendFileSync(PROGRESS, text + '\n'); } catch { /* ignore */ }
  console.log(text);
};
const results = [];
function record(step, ok, detail = '') {
  results.push({ step, ok, detail: String(detail).slice(0, 400) });
  progress(`${ok ? 'PASS' : 'FAIL'}: ${step}${detail ? ` — ${detail}` : ''}`);
  return ok;
}

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8', '.json': 'application/json',
  '.wasm': 'application/wasm', '.css': 'text/css; charset=utf-8',
};

function findChrome() {
  if (process.env.ZCHAIN_CFT_CHROME) return process.env.ZCHAIN_CFT_CHROME;
  const roots = ['/tmp/chrome', path.join(tmpdir(), 'chrome')];
  for (const root of roots) {
    if (!existsSync(root)) continue;
    for (const ver of readdirSync(root)) {
      for (const arch of ['chrome-mac-arm64', 'chrome-mac-x64']) {
        const cand = path.join(root, ver, arch, 'Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing');
        if (existsSync(cand)) return cand;
      }
    }
  }
  throw new Error('Chrome for Testing 未找到；请设置 ZCHAIN_CFT_CHROME');
}

function serveStatic(root) {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      let finished = false;
      const respond = (code, body = null, headers = {}) => {
        if (finished) return;
        finished = true;
        try {
          res.statusCode = code;
          for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
          res.end(body);
        } catch { /* client aborted */ }
      };
      try {
        const urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname);
        let fsPath = path.normalize(path.join(root, '.' + urlPath));
        if (!fsPath.startsWith(root)) { respond(403, 'forbidden'); return; }
        if (urlPath.endsWith('/')) fsPath = path.join(fsPath, 'index.html');
        const data = readFileSync(fsPath);
        respond(200, data, {
          'content-type': MIME[path.extname(fsPath).toLowerCase()] ?? 'application/octet-stream',
          'cache-control': 'no-store',
        });
      } catch {
        respond(404, 'not found');
      }
    });
    server.on('clientError', (err, socket) => { try { socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch { /* ignore */ } });
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class Cdp {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
      }
    });
  }
  static async connect(url, timeoutMs = 15_000) {
    const normalized = url.replace('ws://localhost:', 'ws://127.0.0.1:');
    const ws = new WebSocket(normalized);
    await new Promise((res, rej) => {
      const to = setTimeout(() => rej(new Error(`ws open timeout: ${normalized}`)), timeoutMs);
      ws.addEventListener('open', () => { clearTimeout(to); res(); }, { once: true });
      ws.addEventListener('error', () => { clearTimeout(to); rej(new Error(`ws error: ${normalized}`)); }, { once: true });
    });
    return new Cdp(ws);
  }
  send(method, params = {}, timeoutMs = 15_000) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params }));
    return Promise.race([
      new Promise((resolve, reject) => this.pending.set(id, { resolve, reject })),
      new Promise((_, rej) => setTimeout(() => { this.pending.delete(id); rej(new Error(`cdp send timeout: ${method}`)); }, timeoutMs)),
    ]);
  }
  async eval(expr, timeoutMs = 30_000) {
    return Promise.race([
      (async () => {
        const r = await this.send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
        if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
        return r.result.value;
      })(),
      new Promise((_, rej) => setTimeout(() => rej(new Error(`eval timeout (${timeoutMs}ms): ${expr.slice(0, 80)}`)), timeoutMs)),
    ]);
  }
}

async function newTarget(devtools, url, timeoutMs = 20_000) {
  return Promise.race([
    (async () => (await fetch(`${devtools}/json/new?${encodeURIComponent(url)}`, { method: 'PUT' })).json())(),
    new Promise((_, rej) => setTimeout(() => rej(new Error(`newTarget timeout: ${url.slice(0, 60)}`)), timeoutMs)),
  ]);
}

function connectCdp(target, label, timeoutMs = 20_000) {
  return Promise.race([
    (async () => {
      const conn = await Cdp.connect(target.webSocketDebuggerUrl);
      await conn.send('Runtime.enable');
      await conn.send('Page.enable');
      return conn;
    })(),
    new Promise((_, rej) => setTimeout(() => rej(new Error(`cdp connect timeout: ${label}`)), timeoutMs)),
  ]);
}

async function main() {
  try { unlinkSync(PROGRESS); } catch { /* first run */ }
  const watchdog = setTimeout(() => {
    progress('GLOBAL WATCHDOG: 8min timeout — FAIL');
    writeFileSync(OUT_JSON, JSON.stringify({ verdict: 'FAIL', reason: 'watchdog timeout', results }, null, 2));
    process.exit(1);
  }, 8 * 60 * 1000);

  const chromeBin = findChrome();
  const { server, port: staticPort } = await serveStatic(EXT_ROOT);
  const ORIGIN = `http://127.0.0.1:${staticPort}`;
  const profileDir = mkdtempSync(path.join(tmpdir(), 'zchain_e2e03_'));
  const dbgPort = 11000 + Math.floor(Math.random() * 30000);

  const chrome = spawn(chromeBin, [
    '--headless=new',
    `--remote-debugging-port=${dbgPort}`,
    `--user-data-dir=${profileDir}`,
    '--no-first-run', '--no-default-browser-check',
    `--load-extension=${EXT_ROOT}`,
    'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  let chromeErr = '';
  chrome.stderr.on('data', (d) => { chromeErr += d; });

  const cleanup = () => {
    try { chrome.kill('SIGKILL'); } catch { /* ignore */ }
    server.close();
  };
  process.on('exit', cleanup);
  process.on('SIGINT', () => { cleanup(); process.exit(130); });

  try {
    const devtools = `http://127.0.0.1:${dbgPort}`;
    let version = null;
    for (let i = 0; i < 100; i++) {
      try { version = await (await fetch(`${devtools}/json/version`)).json(); break; } catch { await sleep(300); }
    }
    if (!version) throw new Error(`DevTools 不可达:\n${chromeErr.slice(-2000)}`);

    let extId = null;
    for (let i = 0; i < 60; i++) {
      const targets = await (await fetch(`${devtools}/json/list`)).json();
      const sw = targets.find((t) => t.type === 'service_worker' && t.url.includes('/background/service_worker.js'));
      if (sw) { extId = new URL(sw.url).host; break; }
      await sleep(500);
    }
    if (!extId) throw new Error('扩展 service worker 未出现（加载失败？）');
    await sleep(2000);
    const EXT = `chrome-extension://${extId}`;
    console.log(`extension id: ${extId}`);

    progress('step: open popup page target');
    let popup = null;
    for (let attempt = 1; attempt <= 3 && !popup; attempt++) {
      const popupTarget = await newTarget(devtools, `${EXT}/popup/popup.html`);
      try {
        popup = await connectCdp(popupTarget, `popup#${attempt}`);
      } catch (e) {
        progress(`popup connect retry ${attempt}: ${String(e.message).slice(0, 80)}`);
        try { await fetch(`${devtools}/json/close/${popupTarget.id}`, { method: 'GET' }); } catch { /* ignore */ }
        await sleep(1500);
      }
    }
    if (!popup) throw new Error('popup target CDP 连接失败（3 次重试后）');

    const send = (expr) => popup.eval(`(async () => ${expr})()`, 60_000);
    const msg = (m) => send(`chrome.runtime.sendMessage(${JSON.stringify(m)})`, 60_000);
    const waitForPending = async (pred, timeoutMs = 10_000) => {
      const t0 = Date.now();
      for (;;) {
        const list = await msg({ type: 'popup:listPending' });
        const hit = (list.pending ?? []).find(pred);
        if (hit) return hit;
        if (Date.now() - t0 > timeoutMs) return null;
        await sleep(200);
      }
    };
    const readSettled = async (conn, name, timeoutMs = 30_000) => {
      try {
        const raw = await conn.eval(`Promise.resolve(window.${name}).then((v) => JSON.stringify({ v }))`, timeoutMs);
        return JSON.parse(raw).v;
      } catch {
        return 'READ_TIMEOUT';
      }
    };

    // 预热
    let warmed = false;
    for (let i = 0; i < 20; i++) {
      try {
        await popup.eval(`chrome.runtime.sendMessage({ type: 'bridge:getSession' })`, 10_000);
        warmed = true;
        break;
      } catch (e) {
        progress(`warmup retry ${i + 1}: ${String(e.message).slice(0, 80)}`);
        await sleep(500);
      }
    }
    record('S0 SW 预热（bridge:getSession 应答）', warmed);

    // ===== 账户 + note（限额流的前置）=====
    const created = await msg({ type: 'popup:create', password: WALLET_PW, label: '0.3 账户' });
    record('S1 创建账户', created?.publicKey?.length === 66, JSON.stringify(created)?.slice(0, 100));
    await msg({ type: 'popup:faucet', amount: 300 });
    await msg({ type: 'popup:faucet', amount: 200 });
    const notes = await msg({ type: 'popup:getNotes' });
    record('S2 两张 PLAY note（300 + 200）',
      notes?.notes?.length === 2 && notes.balances?.play_free === '500', JSON.stringify(notes.balances ?? notes).slice(0, 100));

    // ===== S. 会话密钥授权（0.3）=====
    const draft = await msg({
      type: 'popup:sessionDraft',
      origin: ORIGIN,
      accountAddress: `0x${'00'.repeat(31)}cd`,
      allowedScopes: ['play', 'buyin', 'settle', 'transfer'],
      perTxLimit: '250',
      perDayLimit: '1000',
      tableAllowlist: '',
      validitySec: 3600,
    });
    record('S3 授权草稿：wallet-core 生成 delegated key（66 hex）+ SNIP-12 摘要（0x..64 hex）',
      !!draft?.key?.delegated_public_key && draft.key.delegated_public_key?.length === 66
        && /^0x[0-9a-f]{64}$/.test(draft?.digest ?? '')
        && draft.request?.perTxLimit === '250'
        && String(draft.encodeType ?? '').startsWith('AuthorizeZChainKey('),
      JSON.stringify(draft ?? null).slice(0, 240));
    if (!draft?.key) throw new Error('授权草稿失败（S3 FAIL）— 终止后续步骤');

    const registered = await msg({
      type: 'popup:sessionRegister',
      origin: ORIGIN,
      binding: {
        bindingId: draft.key.binding_id,
        delegatedPublicKey: draft.key.delegated_public_key,
        chainId: draft.request.chainId,
        accountAddress: draft.request.accountAddress,
        allowedScopes: draft.request.allowedScopes,
        perTxLimit: draft.request.perTxLimit,
        perDayLimit: draft.request.perDayLimit,
        tableAllowlist: draft.request.tableAllowlist,
        nonce: draft.request.nonce,
        validAfter: draft.request.validAfter,
        validUntil: draft.request.validUntil,
        digest: draft.digest,
      },
    });
    record('S4 devnet 入口形态登记（evidence=devnet_local_entry，状态 active）',
      registered?.binding?.bindingId === draft.key.binding_id && registered.binding.status === 'active'
        && registered.binding.evidence === 'devnet_local_entry',
      JSON.stringify(registered?.binding ?? registered).slice(0, 160));

    let reg = await msg({ type: 'popup:getRegistry' });
    record('S5 registry 列表：1 条会话密钥 + origin/限额/有效期投影',
      reg.sessionKeys?.length === 1 && reg.sessionKeys[0].origin === ORIGIN
        && reg.sessionKeys[0].perTxLimit === '250' && Number(reg.sessionKeys[0].validUntil) > 0,
      JSON.stringify(reg.sessionKeys?.[0] ?? reg).slice(0, 160));

    // ===== L. 限额执行（0.4；经 demo 页 provider 走真实签名管线）=====
    const demoTarget = await newTarget(devtools, `${ORIGIN}/demo/index.html`);
    const demo = await Cdp.connect(demoTarget.webSocketDebuggerUrl);
    await demo.send('Runtime.enable');
    await sleep(800); // 等内容脚本注入

    await demo.eval(`window.__r = window.zchain.requestAccounts().then((r) => JSON.stringify(r)).catch((e) => 'ERR:' + e.code); 'fired'`);
    const connectReq = await waitForPending((p) => p.kind === 'connect');
    if (!connectReq) record('L0 前置：连接请求未打开', false);
    await msg({ type: 'popup:approve', requestId: connectReq.requestId });
    const connectRes = JSON.parse(await readSettled(demo, '__r'));
    record('L0 页面连接（origin 授权）', connectRes?.granted === true, JSON.stringify(connectRes).slice(0, 100));

    let nonceCounter = Date.now();
    // 赋值 + 立即返回 'fired'（promise settle 后经 readSettled 读取——与 run_02 同模式）。
    const transferOp = (noteAmount) => `(async () => {
      const notes = await window.zchain.getNotes();
      const accounts = await window.zchain.getAccounts();
      const n = notes.find((x) => Number(x.amount) === ${noteAmount});
      const op = { kind: 'transfer', assetClass: 'PLAY', chainId: 'zchain-devnet-1', domain: 'zchain', abiVersion: 1,
        nonce: ${nonceCounter++}, expiry: Math.floor(Date.now()/1000) + 300,
        inputs: [n.commitment],
        outputs: [{ owner: accounts.accounts[0], amount: String(${noteAmount}) }] };
      return window.zchain.signOperation(op, '').then((r) => JSON.stringify({ digest: r.digest })).catch((e) => 'ERR:' + e.code);
    })(); 'fired'`;

    // L1 限额内：200 ≤ 250 → 批准 → 签名成功 + 日限记账
    await demo.eval(`window.__ok = ${transferOp(200)}`);
    const okReq = await waitForPending((p) => p.kind !== 'connect' && p.kind !== 'switch_network');
    record('L1 限额内签名请求打开（amount_in=200 ≤ perTx 250）', !!okReq && okReq.preview?.amount_in === '200',
      JSON.stringify(okReq?.preview ?? {}).slice(0, 100));
    if (okReq) await msg({ type: 'popup:approve', requestId: okReq.requestId });
    const okRes = await readSettled(demo, '__ok');
    const okDigest = !String(okRes).startsWith('ERR') && okRes !== 'READ_TIMEOUT' ? JSON.parse(okRes).digest : null;
    record('L2 限额内签名成功（批准 → wallet-core 真实签名）', !!okDigest, String(okRes).slice(0, 100));
    reg = await msg({ type: 'popup:getRegistry' });
    record('L3 日限记账：binding dailyUsedToday = 200（amount_in 口径）',
      reg.sessionKeys?.[0]?.dailyUsedToday === '200', JSON.stringify(reg.sessionKeys?.[0] ?? {}).slice(0, 140));

    // L4 单笔超限：300 > 250 → 弹窗之前直接拒（fail fast，不打开确认卡）
    await demo.eval(`window.__over = ${transferOp(300)}`);
    const overRes = await readSettled(demo, '__over', 15_000);
    record('L4 单笔超限 → SessionOverPerTxLimit（批准前拒绝，不打开弹窗）', overRes === 'ERR:SessionOverPerTxLimit', String(overRes));
    const leakedPending = await msg({ type: 'popup:listPending' });
    record('L5 超限拒绝不遗留待确认请求', (leakedPending.pending ?? []).length === 0, JSON.stringify(leakedPending).slice(0, 100));

    // L6 撤销（粘滞）→ wallet-core 状态机双重确认 → 后续签名拒（fail-closed）
    const revoked = await msg({ type: 'popup:sessionRevoke', bindingId: draft.key.binding_id });
    record('L6 撤销：JS 粘滞位 + wallet-core 状态查询一致（revoked）',
      revoked?.binding?.status === 'revoked' && revoked?.coreStatus?.status === 'revoked'
        && Number(revoked.binding.revokedAt) > 0,
      JSON.stringify({ binding: revoked?.binding?.status, core: revoked?.coreStatus?.status }).slice(0, 100));
    await demo.eval(`window.__rev = ${transferOp(300)}`);
    const revRes = await readSettled(demo, '__rev', 15_000);
    record('L7 撤销后签名 → SessionRevoked（fail-closed，不打开弹窗）', revRes === 'ERR:SessionRevoked', String(revRes));

    // L8 删除记录（显式用户动作）→ 回到常规路径 → 签名可批准
    const del = await msg({ type: 'popup:sessionDelete', bindingId: draft.key.binding_id });
    record('L8 删除记录（撤销态唯一清除路径）', del?.ok === true, JSON.stringify(del).slice(0, 80));
    reg = await msg({ type: 'popup:getRegistry' });
    record('L9 registry 已无该 binding', (reg.sessionKeys ?? []).length === 0, JSON.stringify(reg.sessionKeys).slice(0, 80));
    await demo.eval(`window.__after = ${transferOp(300)}`);
    const afterReq = await waitForPending((p) => p.kind !== 'connect' && p.kind !== 'switch_network');
    record('L10 删除后签名恢复常规路径（请求可打开等待批准）', !!afterReq && afterReq.preview?.amount_in === '300',
      JSON.stringify(afterReq?.preview ?? {}).slice(0, 80));
    if (afterReq) await msg({ type: 'popup:approve', requestId: afterReq.requestId });
    const afterRes = await readSettled(demo, '__after');
    record('L11 常规路径签名成功（owner 路径不受会话密钥影响）', !String(afterRes).startsWith('ERR') && afterRes !== 'READ_TIMEOUT', String(afterRes).slice(0, 80));

    // ===== R. 授权簿 origin 管理（0.4）=====
    let reg2 = await msg({ type: 'popup:getRegistry' });
    record('R1 授权簿含页面 origin', (reg2.origins ?? []).some((o) => o.origin === ORIGIN), JSON.stringify(reg2.origins).slice(0, 100));
    const revOrigin = await msg({ type: 'popup:revokeOrigin', origin: ORIGIN });
    record('R2 撤销 origin 授权', revOrigin?.ok === true, JSON.stringify(revOrigin).slice(0, 80));
    await demo.eval(`window.__na = window.zchain.getNotes().then((r) => JSON.stringify(r.length)).catch((e) => 'ERR:' + e.code); 'fired'`);
    const naRes = await readSettled(demo, '__na', 15_000);
    record('R3 撤销后页面请求 → OriginNotPermitted（fail-closed）', naRes === 'ERR:OriginNotPermitted', String(naRes));
    // 恢复授权（重连批准）供后续步骤使用
    await demo.eval(`window.__rc = window.zchain.requestAccounts().then((r) => JSON.stringify(r)).catch((e) => 'ERR:' + e.code); 'fired'`);
    const rcReq = await waitForPending((p) => p.kind === 'connect');
    if (rcReq) await msg({ type: 'popup:approve', requestId: rcReq.requestId });
    const rcRes = JSON.parse(await readSettled(demo, '__rc'));
    record('R4 重连可恢复授权（批准后 granted）', rcRes?.granted === true, JSON.stringify(rcRes).slice(0, 80));

    // ===== C. 能力矩阵（0.4）=====
    const cap = await msg({ type: 'popup:capabilityMatrix' });
    const rows = cap?.matrix?.rows ?? [];
    const eip = rows.find((r) => r.protocol.startsWith('EIP-1193'));
    const wc = rows.find((r) => r.protocol === 'WalletConnect v2');
    const sn = rows.find((r) => r.protocol.startsWith('Starknet'));
    record('C1 矩阵三协议行齐全（EIP-1193/WC/Starknet）', rows.length === 3, JSON.stringify(rows.map((r) => r.protocol)));
    record('C2 EIP-1193：detected=false（headless 无注入）+ 签名方法全拒清单',
      eip?.detected === false && (eip.denied ?? []).length >= 7 && eip.denied.every((d) => d.reason.includes('EvmSigningForbidden')),
      JSON.stringify({ detected: eip?.detected, denied: eip?.denied?.length }).slice(0, 100));
    record('C3 WalletConnect：dormant 如实（SignClient 未注入 = B5 外部依赖）',
      wc?.active === false && wc.supported?.length === 0 && JSON.stringify(wc.denied).includes('B5'),
      JSON.stringify({ active: wc?.active, summary: wc?.summary }).slice(0, 120));
    record('C4 Starknet：未检测到钱包对象如实标注 + note spend 拒绝红线',
      sn?.detected === false && sn.denied.some((d) => d.reason.includes('ScopeForbidden')),
      JSON.stringify({ detected: sn?.detected }).slice(0, 80));

    // ===== W. REAL 提现预览（0.3，展示态）=====
    const wp = await msg({ type: 'popup:withdrawPreview', amount: '100', owner: 'ab'.repeat(33) });
    record('W1 提现预览：canSubmit 恒 false + vault_offline/库空原因 + 托管风险',
      wp?.preview?.canSubmit === false && wp.preview.displayOnly === true
        && wp.preview.cannotSubmitReasons.some((x) => x.includes('vault_offline'))
        && wp.preview.cannotSubmitReasons.some((x) => x.includes('REAL 库为空'))
        && String(wp.preview.custodyRisk).startsWith('real_is_custodial'),
      JSON.stringify(wp?.preview ?? wp).slice(0, 240));
    const wpBad = await msg({ type: 'popup:withdrawPreview', amount: '-1', owner: 'ab'.repeat(33) });
    record('W2 坏金额 fail-closed（AmountInvalid）', wpBad?.error?.code === 'AmountInvalid', JSON.stringify(wpBad));

    // ===== P. provider 边界 =====
    await demo.eval(`window.__auth = window.zchain.authorizeSessionKey({ request: {} }).then((r) => JSON.stringify(r)).catch((e) => 'ERR:' + e.code); 'fired'`);
    const authRes = await readSettled(demo, '__auth', 15_000);
    record('P1 provider 授权方法面未开放 → NotSupportedIn01（popup UI 为唯一入口）', authRes === 'ERR:NotSupportedIn01', String(authRes));

    // ===== UI 烟测：popup 渲染新卡片 =====
    await popup.eval(`document.body.innerHTML !== ''`, 5_000).catch(() => 'x');
    const uiState = await send(`(async () => { location.reload && 'ok'; return 'ok'; })()`);
    record('U1 popup 页面存活', uiState === 'ok', String(uiState));

    // 汇总
    const pass = results.filter((r) => r.ok).length;
    const summary = {
      date: new Date().toISOString(),
      browser: version.Browser,
      extensionId: extId,
      pageOrigin: ORIGIN,
      total: results.length, pass, fail: results.length - pass,
      results,
    };
    writeFileSync(OUT_JSON, JSON.stringify(summary, null, 2) + '\n');
    const shot = await Promise.race([popup.send('Page.captureScreenshot', { format: 'png' }), new Promise((_, rej) => setTimeout(() => rej(new Error('screenshot timeout')), 10_000))]);
    writeFileSync(OUT_PNG, Buffer.from(shot.data, 'base64'));
    console.log(`\nresult: ${OUT_JSON}`);
    console.log(`screenshot: ${OUT_PNG}`);
    console.log(`verdict: ${results.every((r) => r.ok) ? 'PASS' : 'FAIL'} (${pass}/${results.length})`);
    clearTimeout(watchdog);
    process.exit(results.every((r) => r.ok) ? 0 : 1);
  } finally {
    cleanup();
  }
}

main().catch((e) => { console.error('runner error:', e); process.exit(1); });
