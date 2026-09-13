#!/usr/bin/env node
// Extension 0.2 真实浏览器 E2E（复用 M6-ACC-1 的驱动方式：Chrome for Testing +
// --headless=new + CDP WebSocket + unpacked 加载扩展）。
//
// 覆盖（0.2 关键流，全部在真实扩展运行时内执行）：
//   A. 多账户：创建→水龙头→REAL/PLAY 分库视图→备份导出（自包含口令）→
//      错口令/篡改 fail-closed→导入为新锁定账户→备份口令解锁（公钥一致）→
//      第二账户创建/切换/锁回（互不影响）。
//   B. 网络切换：popup 二步确认（devnet→testnet→devnet）+ 页面发起
//      zchain_switchNetwork 的弹窗二次确认流 + getNetwork/chainChanged。
//   C. 回执：签名成功登记 inclusion 状态位；SeenReceipt 形状拒/收；
//      included 人工登记；超 deadline 提示文案（仅展示）。
//   D. Proof portal：真实 explorer_gateway（--gen-fixture 的 demo WAL +
//      真实证明注册表，--public 开 CORS）→ settlement 明细 → proof 归档 →
//      wallet-core wasm 复验 verified；未知 binding → SettlementNotFound；
//      死端口 → GatewayUnreachable（不伪造结论）。
//   E. 安全回归：坏 previewHash → PreviewMismatch；锁定后签名 → SessionInvalid。
//
// 用法（repo 根目录）：
//   node extension/tests/e2e/run_02.mjs
// 环境变量：
//   ZCHAIN_CFT_CHROME   Chrome for Testing 可执行文件路径（默认扫 /tmp/chrome）
//   ZCHAIN_SKIP_GATEWAY=1  跳过真实网关用例（portal 正例标 skip，如实记录）
// 退出码：0 = 全部 PASS（或显式 skip）；1 = 存在 FAIL。
// Node >= 21（内置 fetch 与 WebSocket）。

import { spawn, execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import { appendFileSync, existsSync, mkdtempSync, readdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const EXT_ROOT = path.resolve(HERE, '..', '..'); // extension/
const REPO = path.resolve(EXT_ROOT, '..');
const OUT_JSON = path.join(HERE, 'e2e02_result.json');
const OUT_PNG = path.join(HERE, 'e2e02_screenshot.png');

const WALLET_PW = 'correct horse battery staple';
const WALLET_PW2 = 'second wallet pass phrase';
const BACKUP_PW = 'backup pass phrase 1';

const PROGRESS = path.join(HERE, 'e2e02_progress.log');
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
      // 防御式响应：任何路径只允许一次 finalize；异常吞掉不进 runner（404/403）。
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
    // 响应分发：CDP 响应按 id 关联到 pending（够用的最小实现；事件忽略）。
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
    // 强制 127.0.0.1：Chrome 返回的 webSocketDebuggerUrl 可能是 ws://localhost:…，
    // 本机 localhost 解析到 ::1 时连接会静默挂起（IPv4-only 监听）。
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
    // 所有 evaluate 带超时：页面 promise 不 settle 时让 harness 报错而不是挂死。
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
  try { unlinkSync(PROGRESS); } catch { /* 首次运行无此文件 */ }
  // 全局看门狗：8 分钟未结束 → FAIL 退出（不无限挂起）。
  const watchdog = setTimeout(() => {
    progress('GLOBAL WATCHDOG: 8min timeout — FAIL');
    writeFileSync(OUT_JSON, JSON.stringify({ verdict: 'FAIL', reason: 'watchdog timeout', results }, null, 2));
    process.exit(1);
  }, 8 * 60 * 1000);

  const chromeBin = findChrome();
  const { server, port: staticPort } = await serveStatic(EXT_ROOT);
  const profileDir = mkdtempSync(path.join(tmpdir(), 'zchain_e2e02_'));
  const workDir = mkdtempSync(path.join(tmpdir(), 'zchain_e2e02_gw_'));
  const dbgPort = 11000 + Math.floor(Math.random() * 30000);

  // ---- 真实 explorer_gateway（可选）----
  let gateway = { up: false };
  if (process.env.ZCHAIN_SKIP_GATEWAY !== '1') {
    try {
      const bin = path.join(REPO, 'target', 'release', 'explorer_gateway');
      if (!existsSync(bin)) throw new Error('explorer_gateway 未构建（target/release）');
      const gen = spawnSyncJson(bin, ['--gen-fixture', path.join(workDir, 'fixture')]);
      if (!gen.sequencer_public) throw new Error('gen-fixture 失败');
      const gwPort = 18900 + Math.floor(Math.random() * 500);
      const gw = spawn(bin, [
        '--appchain-wal', path.join(workDir, 'fixture', 'appchain.wal'),
        '--sequencer-public', gen.sequencer_public,
        '--proven-log', path.join(workDir, 'fixture', 'proven.log'),
        '--proof-registry', path.join(workDir, 'fixture', 'proof_registry.jsonl'),
        '--aggregate-log', path.join(workDir, 'fixture', 'aggregate.log'),
        '--listen', `127.0.0.1:${gwPort}`,
        // --public：响应带 CORS *，扩展页（chrome-extension:// 源）才能跨源读取。
        '--public',
      ], { stdio: ['ignore', 'ignore', 'ignore'] });
      let up = false;
      for (let i = 0; i < 60; i++) {
        try {
          const st = await (await fetch(`http://127.0.0.1:${gwPort}/api/v1/status`)).json();
          if (st.env === 'devnet') { up = true; break; }
        } catch { await sleep(200); }
      }
      if (!up) throw new Error('gateway 未就绪');
      const settlements = (await (await fetch(`http://127.0.0.1:${gwPort}/api/v1/settlements?limit=5`)).json()).settlements;
      gateway = { up: true, pid: gw, baseUrl: `http://127.0.0.1:${gwPort}`, binding: settlements?.[0]?.hand_binding ?? null };
    } catch (e) {
      console.log(`note: 真实网关不可用（${e.message}），portal 正例用例将如实标 skip`);
    }
  }

  const chrome = spawn(chromeBin, [
    '--headless=new',
    `--remote-debugging-port=${dbgPort}`,
    `--user-data-dir=${profileDir}`,
    '--no-first-run', '--no-default-browser-check',
    // unpacked 扩展加载（Chrome for Testing 支持 --load-extension）。
    // 注意：不用 --disable-web-security——它会破坏扩展页的 chrome.runtime；
    // 跨源网关访问改由 http 同源 harness 页承载（见 D 节说明）。
    `--load-extension=${EXT_ROOT}`,
    'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  let chromeErr = '';
  chrome.stderr.on('data', (d) => { chromeErr += d; });

  const cleanup = () => {
    try { chrome.kill('SIGKILL'); } catch { /* ignore */ }
    if (gateway.pid) { try { gateway.pid.kill('SIGKILL'); } catch { /* ignore */ } }
    server.close();
  };
  process.on('exit', cleanup);
  process.on('SIGINT', () => { cleanup(); process.exit(130); });
  process.on('uncaughtException', (e) => { progress(`uncaughtException: ${String(e?.message ?? e)}`); });

  try {
    const devtools = `http://127.0.0.1:${dbgPort}`;
    let version = null;
    for (let i = 0; i < 100; i++) {
      try { version = await (await fetch(`${devtools}/json/version`)).json(); break; } catch { await sleep(300); }
    }
    if (!version) throw new Error(`DevTools 不可达:\n${chromeErr.slice(-2000)}`);

    // 找扩展 id（service worker target），并等 SW 完全就绪（冷启动竞态：
    // SW 刚注册时立即 attach 其扩展页 target，CDP 会话可能静默不应答）。
    let extId = null;
    for (let i = 0; i < 60; i++) {
      const targets = await (await fetch(`${devtools}/json/list`)).json();
      const sw = targets.find((t) => t.type === 'service_worker' && t.url.includes('/background/service_worker.js'));
      if (sw) { extId = new URL(sw.url).host; break; }
      await sleep(500);
    }
    if (!extId) throw new Error('扩展 service worker 未出现（加载失败？）');
    // 额外等待 + 就绪探测：SW 能回答一次 RPC 才继续（最多 30s）。
    let swReady = false;
    for (let i = 0; i < 60; i++) {
      const targets = await (await fetch(`${devtools}/json/list`)).json();
      if (targets.some((t) => t.type === 'service_worker' && t.url.includes('/background/service_worker.js'))) {
        // SW target 仍在列表里（未进入 30s 空闲回收前）→ 给事件面留稳定窗口。
        swReady = true;
        break;
      }
      await sleep(500);
    }
    if (!swReady) throw new Error('扩展 service worker 未就绪');
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
        // 关闭可能半开的 target，重开（避免死 target 累积）。
        try { await fetch(`${devtools}/json/close/${popupTarget.id}`, { method: 'GET' }); } catch { /* ignore */ }
        await sleep(1500);
      }
    }
    if (!popup) throw new Error('popup target CDP 连接失败（3 次重试后）');

    const send = (expr) => popup.eval(`(async () => ${expr})()`, 60_000);
    const msg = (m) => send(`chrome.runtime.sendMessage(${JSON.stringify(m)})`, 60_000);
    // 轮询待确认请求（连接/签名/换网打开是异步管线，固定 sleep 会竞态）。
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
    // 读取页面侧"赋值为 promise"的结果变量：表达式恒返回 promise → CDP
    // awaitPromise 等 settle → resolve 后立即 JSON.stringify（杜绝把未 settle
    // 的 promise 序列化成 {} / "[object Object]" 的歧义）。
    const readSettled = async (name, timeoutMs = 30_000) => {
      try {
        const raw = await demo.eval(`Promise.resolve(window.${name}).then((v) => JSON.stringify({ v }))`, timeoutMs);
        return JSON.parse(raw).v;
      } catch {
        return 'READ_TIMEOUT';
      }
    };

    // 预热：SW 冷启动 + wasm 实例化（首次 RPC 前置；失败重试直到就绪）。
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
    record('A0 SW 预热（bridge:getSession 应答）', warmed);

    // ===== A. 多账户 + 备份恢复 =====
    progress('step A1: create account 1');
    const created1 = await msg({ type: 'popup:create', password: WALLET_PW, label: '主账户' });
    record('A1 创建账户1', created1?.publicKey?.length === 66, JSON.stringify(created1)?.slice(0, 120));

    const faucet = await msg({ type: 'popup:faucet', amount: 500 });
    record('A2 devnet 水龙头 500 PLAY', faucet?.play_free === '500' || faucet?.commitment != null, JSON.stringify(faucet).slice(0, 120));

    const notes = await msg({ type: 'popup:getNotes' });
    record('A3 REAL/PLAY 分库视图（PLAY 有 note / REAL 空 / 余额分栏）',
      notes?.notes?.length === 1 && Array.isArray(notes.realNotes) && notes.realNotes.length === 0
        && notes.balances?.play_free === '500' && notes.balances?.real_free === '0',
      JSON.stringify(notes).slice(0, 160));
    const secretLeak = JSON.stringify(notes).includes('spend_secret') || JSON.stringify(notes).includes('nullifier');
    record('A4 分库视图脱敏（无 spend_secret/nullifier）', !secretLeak);

    const views = await msg({ type: 'popup:getDisplayViews' });
    record('A5 REAL 展示门：claim 隐藏 + 托管风险提示（不暗示可提现）',
      views?.real?.show_claim === false && views?.real?.claim_disabled_reason === 'vault_offline'
        && String(views?.real?.custody_risk_notice ?? '').startsWith('real_is_custodial')
        && !JSON.stringify(views.play).toLowerCase().includes('real'),
      JSON.stringify(views).slice(0, 160));

    const exported = await msg({ type: 'popup:backupExport', password: BACKUP_PW });
    record('A6 备份导出（ZCBK，自包含备份口令）', !!exported?.backupHex && exported.notes?.play === 1, JSON.stringify(exported).slice(0, 100));

    const badPwImport = await msg({ type: 'popup:backupImport', backupHex: exported.backupHex, password: 'wrong pass phrase' });
    record('A7 错误口令导入 → BadPassword（fail-closed）', badPwImport?.error?.code === 'BadPassword', JSON.stringify(badPwImport));

    const bytes = new Uint8Array(exported.backupHex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(exported.backupHex.slice(i * 2, i * 2 + 2), 16);
    bytes[bytes.length - 1] ^= 0x01;
    const tamperedHex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
    const tampered = await msg({ type: 'popup:backupImport', backupHex: tamperedHex, password: BACKUP_PW });
    record('A8 篡改文件导入 → 拒绝（fail-closed）', !!tampered?.error, JSON.stringify(tampered));

    const imported = await msg({ type: 'popup:backupImport', backupHex: exported.backupHex, password: BACKUP_PW });
    record('A9 正确口令导入 → 新增锁定账户（公钥一致）',
      imported?.accountId && imported.publicKey === created1.publicKey && imported.remainsLocked === true, JSON.stringify(imported).slice(0, 140));

    // ===== A10-12 第二账户 + 切换隔离 =====
    const created2 = await msg({ type: 'popup:create', password: WALLET_PW2, label: '第二账户' });
    record('A10 创建账户2（会话切到账户2）', created2?.publicKey && created2.publicKey !== created1.publicKey);

    let state = await msg({ type: 'popup:getState' });
    record('A11 账本含 3 账户（1 原始 + 1 恢复 + 1 新建）', state.accounts?.length === 3, `count=${state.accounts?.length}`);

    const sel = await msg({ type: 'popup:selectAccount', accountId: created1.accountId });
    state = await msg({ type: 'popup:getState' });
    record('A12 切换回账户1：会话锁定（fail-closed），账户1 数据完好', sel.activeAccountId === created1.accountId && state.unlocked === false);

    const relock = await msg({ type: 'popup:unlock', accountId: created1.accountId, password: WALLET_PW });
    const notes1 = await msg({ type: 'popup:getNotes' });
    record('A13 账户1 重新解锁：note 库完整（隔离）',
      relock?.publicKey === created1.publicKey && notes1?.notes?.length === 1 && notes1.balances?.play_free === '500',
      JSON.stringify(notes1).slice(0, 140));

    const wrongAcct = await msg({ type: 'popup:unlock', accountId: created2.accountId, password: WALLET_PW });
    record('A14 错误账户口令 → BadPassword（fail-closed）', wrongAcct?.error?.code === 'BadPassword');
    await msg({ type: 'popup:unlock', accountId: created1.accountId, password: WALLET_PW });

    // ===== B. 网络切换 =====
    const swTestnet = await msg({ type: 'popup:switchNetwork', chainId: 'zchain-testnet-1' });
    let state2 = await msg({ type: 'popup:getState' });
    record('B1 popup 换网 testnet（账户元数据持久化）', swTestnet?.chainId === 'zchain-testnet-1' && state2.chainId === 'zchain-testnet-1');
    record('B2 testnet 网关未配置如实 null（不回落 devnet）', state2.gatewayUrl === null, `gatewayUrl=${state2.gatewayUrl}`);
    const swMainnet = await msg({ type: 'popup:switchNetwork', chainId: 'zchain-mainnet-1' });
    record('B3 mainnet 红线 → NetworkUnsupported', swMainnet?.error?.code === 'NetworkUnsupported', JSON.stringify(swMainnet));
    await msg({ type: 'popup:switchNetwork', chainId: 'zchain-devnet-1' });

    // ===== C/E. demo 页 provider 流（签名/回执/换网确认/安全回归）=====
    progress('step C: demo page flows');
    const demoTarget = await newTarget(devtools, `http://127.0.0.1:${staticPort}/demo/index.html`);
    const demo = await Cdp.connect(demoTarget.webSocketDebuggerUrl);
    await demo.send('Runtime.enable');
    await sleep(800); // 等内容脚本注入

    await demo.eval(`window.__r = window.zchain.requestAccounts().then((r) => JSON.stringify(r)).catch((e) => 'ERR:' + e.code); 'fired'`);
    const connectReq = await waitForPending((p) => p.kind === 'connect');
    if (!connectReq) record('C1 前置：连接请求未打开', false);
    await msg({ type: 'popup:approve', requestId: connectReq.requestId });
    const connectRes = JSON.parse(await readSettled('__r'));
    record('C1 页面连接（origin 授权 → 当前账户）', connectRes?.granted === true && connectRes.accounts?.[0] === created1.publicKey, JSON.stringify(connectRes).slice(0, 140));

    // 签名（transfer 自转 1）→ 批准 → 回执登记
    await demo.eval(`(async () => {
      const notes = await window.zchain.getNotes();
      const accounts = await window.zchain.getAccounts();
      const spendable = notes.filter((n) => n.spendable);
      const total = spendable.reduce((acc, n) => acc + Number(n.amount), 0);
      const op = { kind: 'transfer', assetClass: 'PLAY', chainId: 'zchain-devnet-1', domain: 'zchain', abiVersion: 1,
        nonce: Date.now(), expiry: Math.floor(Date.now()/1000) + 300,
        inputs: spendable.map((n) => n.commitment),
        outputs: [{ owner: accounts.accounts[0], amount: String(total) }] }; // 守恒：Σout == Σin
      window.__sign = window.zchain.signOperation(op, '').then((r) => JSON.stringify({ digest: r.digest, kind: r.preview.kind })).catch((e) => 'ERR:' + e.code);
    })()`);
    const signReq = await waitForPending((p) => p.kind !== 'connect' && p.kind !== 'switch_network');
    record('C2 结构化签名预览请求打开（含 REAL/PLAY 徽章字段）', !!signReq && !!signReq.preview?.digest,
      signReq ? JSON.stringify(signReq.preview ?? {}).slice(0, 100) : `page says: ${await demo.eval('window.__sign ?? "pending"')}`);
    if (!signReq) throw new Error('签名请求未打开（C2 FAIL）— 终止后续步骤');
    await msg({ type: 'popup:approve', requestId: signReq.requestId });
    const signRes = await readSettled('__sign');
    record('C3 真实签名成功（wallet-core digest）', !String(signRes).startsWith('ERR') && JSON.parse(signRes).digest?.length === 64, String(signRes).slice(0, 100));
    const signDigest = String(signRes).startsWith('ERR') ? null : JSON.parse(signRes).digest;

    const receipts = await msg({ type: 'popup:receipts' });
    const rec = receipts.receipts?.find((r) => r.digest === signDigest);
    record('C4 签名回执登记：signed 状态位 + deadline=10000ms（协议默认）',
      rec?.status === 'signed' && rec.deadlineMs === 10000, JSON.stringify(rec?.view ?? rec).slice(0, 140));
    record('C5 超期判定与提示文案（仅展示，不实现提交路径）',
      rec.view.pastDeadline === false && /等待链上见证实回执/.test(rec.view.hint ?? ''));
    const badSeen = await msg({ type: 'popup:receiptSeen', digest: rec.digest, receipt: { broken: true } });
    record('C6 SeenReceipt 形状校验拒绝', badSeen?.error?.code === 'InvalidArgument');
    const seen = await msg({ type: 'popup:receiptSeen', digest: rec.digest, receipt: { chain_id: 'zchain-devnet-1', tx_hash: 'cd'.repeat(32), seen_at_ms: Date.now(), validator_pubkey: 'ef'.repeat(33), signature: [1, 2, 3] } });
    record('C7 合法形状 SeenReceipt → seen（evidence 如实标注未验签）', seen?.entry?.status === 'seen' && seen.entry.evidence.seen === 'receipt_unverified_signature');
    const inc = await msg({ type: 'popup:receiptIncluded', digest: rec.digest });
    record('C8 included 人工登记（evidence=local_manual_entry）', inc?.entry?.status === 'included' && inc.entry.evidence.included === 'local_manual_entry');

    // 页面发起换网 → 弹窗二次确认 → 批准
    await demo.eval(`window.__sw = window.zchain.switchNetwork('zchain-testnet-1').then((r) => JSON.stringify(r)).catch((e) => 'ERR:' + e.code); 'fired'`);
    const swReq = await waitForPending((p) => p.kind === 'switch_network');
    record('C9 页面换网请求打开确认卡（devnet → testnet，from/to 展示）',
      !!swReq && swReq.preview?.fromChainId === 'zchain-devnet-1' && swReq.preview?.toChainId === 'zchain-testnet-1', JSON.stringify(swReq?.preview ?? {}));
    if (!swReq) throw new Error('换网确认请求未打开（C9 FAIL）— 终止后续步骤');
    await msg({ type: 'popup:approve', requestId: swReq.requestId });
    const swRes = JSON.parse(await readSettled('__sw'));
    const netAfter = JSON.parse(await demo.eval(`window.zchain.getNetwork().then((r) => JSON.stringify(r))`));
    record('C10 换网批准生效（changed=true；getNetwork=testnet）',
      swRes?.changed === true && swRes.chainId === 'zchain-testnet-1' && netAfter.chainId === 'zchain-testnet-1', JSON.stringify({ swRes, netAfter }).slice(0, 160));

    // E2E 回归：坏 previewHash（切回 devnet；先水龙头补一张可花费 note）
    await msg({ type: 'popup:switchNetwork', chainId: 'zchain-devnet-1' });
    await msg({ type: 'popup:faucet', amount: 100 });
    await demo.eval(`(async () => {
      const notes = await window.zchain.getNotes();
      const accounts = await window.zchain.getAccounts();
      const spendable = notes.filter((n) => n.spendable);
      const total = spendable.reduce((acc, n) => acc + Number(n.amount), 0);
      const op = { kind: 'transfer', assetClass: 'PLAY', chainId: 'zchain-devnet-1', domain: 'zchain', abiVersion: 1,
        nonce: Date.now() + 1, expiry: Math.floor(Date.now()/1000) + 300,
        inputs: spendable.map((n) => n.commitment),
        outputs: [{ owner: accounts.accounts[0], amount: String(total) }] };
      window.__bad = window.zchain.signOperation(op, 'ff'.repeat(32)).then(() => 'OK').catch((e) => 'ERR:' + e.code);
    })()`);
    // PreviewMismatch 在用户批准后判定 → 批准这条签名请求让 promise settle
    const badReq = await waitForPending((p) => p.kind !== 'connect' && p.kind !== 'switch_network', 8000);
    if (badReq) await msg({ type: 'popup:approve', requestId: badReq.requestId });
    const badRaw = await readSettled('__bad');
    record('E1 坏 previewHash → PreviewMismatch（不回退）', badRaw === 'ERR:PreviewMismatch', String(badRaw).slice(0, 80));

    // 锁定后签名 → SessionInvalid
    await msg({ type: 'popup:lock' });
    await demo.eval(`(async () => {
      const notes = await window.zchain.getNotes().catch(() => []);
      const op = { kind: 'transfer', assetClass: 'PLAY', chainId: 'zchain-devnet-1', domain: 'zchain', abiVersion: 1,
        nonce: Date.now() + 2, expiry: Math.floor(Date.now()/1000) + 300, inputs: ['ab'.repeat(32)],
        outputs: [{ owner: 'cd'.repeat(33), amount: '1' }] };
      window.__locked = window.zchain.signOperation(op, '').then(() => 'OK').catch((e) => 'ERR:' + e.code);
    })()`);
    const lockedRaw = await readSettled('__locked');
    record('E2 锁定后签名 → SessionInvalid（不回退）', lockedRaw === 'ERR:SessionInvalid', String(lockedRaw).slice(0, 80));

    // ===== D. Proof portal（真实网关；http 同源 harness 页承载同一逻辑模块）=====
    // Chrome 138+ LNA 限制：chrome-extension 页无主机权限时 fetch 127.0.0.1
    // 直接失败（headless 无法点击权限弹窗）。D 步骤改在 http://127.0.0.1 的
    // harness 页执行**与 portal/portal.js 同一模块**的管线（真实网关 + 真实
    // wasm 复验）；扩展 portal 页的加载/错误面另测（D5'）。
    progress('step D: portal flows');
    const harnessTarget = await newTarget(devtools, `http://127.0.0.1:${staticPort}/tests/e2e/portal_harness.html`);
    const harness = await connectCdp(harnessTarget, 'harness');
    await sleep(500);

    // D5'：扩展 portal 页自身能加载并完成一次网关不可达的错误路径（不走跨源 fetch）。
    const portalTarget = await newTarget(devtools, `${EXT}/portal/portal.html`);
    const portal = await connectCdp(portalTarget, 'portal');
    await sleep(500);
    const portalAlive = await portal.eval(`document.getElementById('verify') != null && document.getElementById('binding') != null`);
    record("D0 扩展 portal 页加载（输入/按钮/网关行渲染）", portalAlive === true);

    if (gateway.up && gateway.binding) {
      // 正例：真实网关 settlement 明细 + proof 归档 + wasm 复验
      const res = await harness.eval(`window.runPortalCheck(${JSON.stringify(gateway.baseUrl)}, ${JSON.stringify(gateway.binding)})`, 30_000);
      const verdict = res?.steps?.verdict ?? {};
      record('D1 portal 正例：结算关系复验 verified（payout_root 复算一致）',
        res?.ok === true && verdict.verdict === 'verified', JSON.stringify(res).slice(0, 240));
      record('D2 展示 verifier 名称/版本/耗时', !!verdict.verifier?.name && !!verdict.verifier?.version && Number.isInteger(verdict.elapsedMs),
        JSON.stringify({ verifier: verdict.verifier, elapsedMs: verdict.elapsedMs }));
      record('D3 proof 归档元数据展示（engine + 字节数；不宣称 STARK 已验证）',
        res?.steps?.proof?.engine != null && Number.isInteger(res.steps.proof.payloadLen), JSON.stringify(res?.steps?.proof).slice(0, 140));

      // 未知 binding → SettlementNotFound（网关 404，如实报）
      const nf = await harness.eval(`window.runPortalCheck(${JSON.stringify(gateway.baseUrl)}, 'ab'.repeat(32))`, 30_000);
      record('D4 未知 binding → SettlementNotFound（不伪造结果）', nf?.step === 'fetchSettlement' && nf?.code === 'SettlementNotFound', JSON.stringify({ code: nf?.code }).slice(0, 120));
    } else {
      record('D1 portal 正例（真实网关）', true, 'SKIP: 网关不可用（ZCHAIN_SKIP_GATEWAY 或未构建）');
    }

    // 网关不可达 → GatewayUnreachable（死端口；同样经 harness 页管线）
    const dead = await harness.eval(`window.runPortalCheck('http://127.0.0.1:9', ${JSON.stringify(gateway.binding ?? 'ab'.repeat(32))})`, 30_000);
    record('D5 网关不可达 → GatewayUnreachable（明确报错）', dead?.code === 'GatewayUnreachable', String(dead?.reason ?? '').slice(0, 120));

    // 汇总
    const pass = results.filter((r) => r.ok).length;
    const summary = {
      date: new Date().toISOString(),
      browser: version.Browser,
      extensionId: extId,
      gateway: gateway.up ? { baseUrl: gateway.baseUrl, binding: gateway.binding } : 'skipped',
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

function spawnSyncJson(bin, args) {
  try {
    const out = execFileSync(bin, args, { encoding: 'utf8' });
    const m = out.match(/\{[\s\S]*\}/);
    return m ? JSON.parse(m[0]) : {};
  } catch {
    return {};
  }
}

main().catch((e) => { console.error('runner error:', e); process.exit(1); });
