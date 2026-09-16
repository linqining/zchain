#!/usr/bin/env node
// =============================================================================
// scripts/poker_air_browser.mjs — 真实浏览器（Chrome for Testing）+ ZChain
// 钱包扩展打牌自动化。
//
// 流程：
//   1. 启动 Chrome（headless=new，--load-extension 加载 ZChain 扩展）；
//   2. popup 一键创建钱包（口令自动保存到运行目录）；
//   3. devnet 水龙头铸造 PLAY note（签名输入）；
//   4. 打开 poker 客户端 → Log In → "ZChain Wallet" 按钮（扩展弹窗批准
//      连接 + 登录签名，经 popup:listPending/popup:approve 消息驱动）；
//   5. /play 桌面 → Sit Down → 买入弹窗确认（扩展批准 buy_in 签名）；
//   6. 自动跟牌循环（Check 优先、其次 Call/Fold），直到
//      GET /api/tables/1/history 达到 TARGET_HANDS。
//
// 环境变量：
//   POKER_URL（默认 http://localhost:5173） GAME_API（默认 http://127.0.0.1:9001）
//   EXT_PATH（默认仓库 extension/） TARGET_HANDS（默认 100）
//   SEAT（默认 4） BUYIN（默认 1000） TIMEOUT_SECS（默认 14400）
//   CHROME_BIN（默认自动探测 /tmp/chrome） KEEP_CHROME=1（退出不杀浏览器）
// 退出码：0 = 打满 TARGET_HANDS；1 = 超时/失败。
// =============================================================================

import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, appendFileSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

const REPO_ROOT = path.resolve(HERE, '..');
const POKER_URL = process.env.POKER_URL ?? 'http://localhost:5173';
const GAME_API = process.env.GAME_API ?? 'http://127.0.0.1:9001';
const EXT_PATH = process.env.EXT_PATH ?? path.join(REPO_ROOT, 'extension');
const TARGET_HANDS = Number(process.env.TARGET_HANDS ?? 100);
const SEAT = Number(process.env.SEAT ?? 4);
const BUYIN = Number(process.env.BUYIN ?? 1000);
const TIMEOUT_SECS = Number(process.env.TIMEOUT_SECS ?? 14400);
const RUN_DIR = process.env.POKER_AIR_RUN_DIR ?? '/tmp/poker-air-zchain';
const LOG = path.join(RUN_DIR, 'browser.log');

mkdirSync(RUN_DIR, { recursive: true });
const progress = (line) => {
  const text = `[${new Date().toISOString()}] ${line}`;
  try { appendFileSync(LOG, text + '\n'); } catch { /* ignore */ }
  console.log(text);
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function findChrome() {
  if (process.env.CHROME_BIN) return process.env.CHROME_BIN;
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
  throw new Error('Chrome for Testing 未找到；请设置 CHROME_BIN');
}

class Cdp {
  constructor(ws, tag = 'cdp') {
    this.ws = ws;
    this.tag = tag;
    this.id = 0;
    this.pending = new Map();
    ws.addEventListener('close', () => progress(`[cdp:${tag}] websocket CLOSED`));
    ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.method === 'Runtime.consoleAPICalled' && ['log', 'warn', 'error', 'debug', 'info'].includes(msg.params?.type)) {
        const text = (msg.params.args ?? []).map((a) => {
          const v = a.value ?? a.description ?? '';
          return typeof v === 'object' ? JSON.stringify(v)?.slice(0, 120) : String(v);
        }).join(' ').slice(0, 300);
        if (Date.now() - (globalThis.__consoleUntil ?? 0) > 0 || /shuffle|Shuffle|keys|panic|error/i.test(text)) {
          progress(`[page:${this.tag}] ${text}`);
        }
      }
      if (msg.method === 'Runtime.exceptionThrown') {
        progress(`[page:${this.tag}] EXCEPTION: ${JSON.stringify(msg.params?.exceptionDetails)?.slice(0, 400)}`);
      }
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
      }
    });
  }
  static async connectRaw(url) {
    const ws = new WebSocket(url.replace('ws://localhost:', 'ws://127.0.0.1:'));
    await new Promise((res, rej) => {
      ws.addEventListener('open', res, { once: true });
      ws.addEventListener('error', rej, { once: true });
    });
    return { ws };
  }
  send(method, params = {}) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
  }
  async eval(expr, timeoutMs = 30_000) {
    return Promise.race([
      (async () => {
        const r = await this.send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
        if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
        return r.result.value;
      })(),
      new Promise((_, rej) => setTimeout(() => rej(new Error(`eval timeout: ${expr.slice(0, 80)}`)), timeoutMs)),
    ]);
  }
  close() { try { this.ws.close(); } catch { /* ignore */ } }
}

async function newTarget(devtools, url, timeoutMs = 20_000) {
  return Promise.race([
    (async () => (await fetch(`${devtools}/json/new?${encodeURIComponent(url)}`, { method: 'PUT' })).json())(),
    new Promise((_, rej) => setTimeout(() => rej(new Error(`newTarget timeout: ${url.slice(0, 60)}`)), timeoutMs)),
  ]);
}

async function connectCdp(target, label, timeoutMs = 20_000) {
  return Promise.race([
    (async () => {
      const conn = new Cdp((await Cdp.connectRaw(target.webSocketDebuggerUrl)).ws, label);
      await conn.send('Runtime.enable');
      await conn.send('Page.enable');
      return conn;
    })(),
    new Promise((_, rej) => setTimeout(() => rej(new Error(`cdp connect timeout: ${label}`)), timeoutMs)),
  ]);
}

async function closeTarget(devtools, targetId) {
  await fetch(`${devtools}/json/close/${targetId}`).catch(() => { });
}

// ---------------------------------------------------------------------------
// popup 消息驱动（审批 = popup:listPending + popup:approve，比找按钮稳）。
// ---------------------------------------------------------------------------

async function popupSend(page, msg, timeoutMs = 15_000) {
  return page.eval(`chrome.runtime.sendMessage(${JSON.stringify(msg)})`, timeoutMs);
}

/** 循环审批扩展的全部待定请求（连接/签名/换网），直到 quiet。 */
async function drainApprovals(page, label, maxRounds = 20) {
  for (let i = 0; i < maxRounds; i++) {
    let pending = null;
    try {
      pending = await popupSend(page, { type: 'popup:listPending' }, 10_000);
    } catch (e) {
      progress(`[approve:${label}] listPending failed: ${e.message}`);
      return;
    }
    const list = pending?.pending ?? [];
    if (list.length === 0) return;
    for (const p of list) {
      progress(`[approve:${label}] approve kind=${p.kind} method=${p.method ?? ''} origin=${p.origin}`);
      await popupSend(page, { type: 'popup:approve', requestId: p.requestId }, 30_000);
      await sleep(600);
    }
    await sleep(800);
  }
}

async function waitForExpr(page, expr, timeoutMs = 15_000, interval = 300) {
  const t0 = Date.now();
  for (;;) {
    let v = null;
    try { v = await page.eval(expr, 5_000); } catch { /* 渲染瞬间 */ }
    if (v) return v;
    if (Date.now() - t0 > timeoutMs) return null;
    await sleep(interval);
  }
}

// 手数口径 = 结算桥已锚定数（appchain proven 结算 → zchain tx）。
// history 端点会混入洗牌超时等未结算的废手，不能作为验收计数。
const BRIDGE_STATE = process.env.BRIDGE_STATE ?? path.join(RUN_DIR, 'bridge_state.json');
async function anchoredCount() {
  try {
    const raw = readFileSync(BRIDGE_STATE, 'utf8');
    const state = JSON.parse(raw);
    return Object.keys(state.anchored ?? {}).length;
  } catch {
    return 0;
  }
}

/**
 * 区块链浏览器（extension Proof Portal）验收：在同一真实浏览器里打开
 * portal，填入最后一笔已锚定结算的 hand binding，点"拉取并本地验证"，
 * 断言结算明细/验证结论渲染成功并截图存证。
 */
async function verifyOnPortal(devtools, extId) {
  try {
    let binding = null;
    try {
      const state = JSON.parse(readFileSync(path.join(RUN_DIR, 'bridge_state.json'), 'utf8'));
      const keys = Object.keys(state.anchored ?? {});
      binding = keys[keys.length - 1] ?? null;
    } catch { /* no state */ }
    if (!binding) {
      progress('[portal] 无已锚定 binding，跳过区块链浏览器验收');
      return false;
    }
    const portalTarget = await newTarget(devtools, `chrome-extension://${extId}/portal/portal.html`);
    const portal = await connectCdp(portalTarget, 'portal');
    const ready = await waitForExpr(portal, `!!document.getElementById('binding') && !!document.getElementById('verify')`, 20_000);
    if (!ready) {
      await screenshot(portal, 'portal-not-ready');
      progress('[portal] FAIL: portal 页面未就绪');
      return false;
    }
    const gatewayLine = await portal.eval(`document.getElementById('gateway-line')?.innerText ?? ''`, 5_000);
    progress(`[portal] 打开区块链浏览器（${gatewayLine.slice(0, 80)}），binding=${binding.slice(0, 16)}…`);
    await portal.eval(`(() => {
      const n = document.getElementById('binding');
      n.value = ${JSON.stringify(binding)};
      n.dispatchEvent(new Event('input', { bubbles: true }));
      document.getElementById('verify').click();
      return true;
    })()`);
    const shown = await waitForExpr(portal, `(() => {
      const card = document.getElementById('settlement-card');
      return card && card.style.display !== 'none' && (document.getElementById('settlement-body')?.innerText?.length ?? 0) > 40 ? true : null;
    })()`, 30_000);
    if (!shown) {
      const err = await portal.eval(`document.getElementById('err')?.innerText ?? ''`, 5_000).catch(() => '');
      await screenshot(portal, 'portal-fail');
      progress(`[portal] FAIL: 结算明细未渲染 err=${err.slice(0, 160)}`);
      return false;
    }
    const detail = await portal.eval(`document.getElementById('settlement-body')?.innerText ?? ''`, 5_000);
    const verdict = await waitForExpr(portal, `(() => {
      const v = document.getElementById('verdict-body');
      return v && v.innerText.length > 0 ? v.innerText.slice(0, 300) : null;
    })()`, 30_000);
    progress(`[portal] ✓ 区块链浏览器已展示结算明细（${detail.split('\n').slice(0, 4).join(' | ').slice(0, 200)}）`);
    if (verdict) progress(`[portal] 本地验证结论: ${verdict.replace(/\n/g, ' | ').slice(0, 260)}`);
    await sleep(800);
    await screenshot(portal, 'portal-verified');
    return true;
  } catch (e) {
    progress(`[portal] EXC: ${e.message}`);
    return false;
  }
}

async function screenshot(page, name) {
  try {
    const shot = await Promise.race([
      page.send('Page.captureScreenshot', { format: 'png' }),
      new Promise((_, rej) => setTimeout(() => rej(new Error('screenshot timeout')), 10_000)),
    ]);
    const file = path.join(RUN_DIR, `${name}.png`);
    writeFileSync(file, Buffer.from(shot.data, 'base64'));
    progress(`[shot] ${file}`);
  } catch (e) {
    progress(`[shot] ${name} failed: ${e.message}`);
  }
}

// ---------------------------------------------------------------------------
// 主流程。
// ---------------------------------------------------------------------------

async function main() {
  const startedAt = Date.now();
  const chromeBin = findChrome();
  const profileDir = mkdtempSync(path.join(tmpdir(), 'poker_air_chrome_'));
  const dbgPort = Number(process.env.DEBUG_PORT ?? (11000 + Math.floor(Math.random() * 30000)));
  progress(`chrome=${chromeBin} profile=${profileDir} debug=${dbgPort}`);
  const chrome = spawn(chromeBin, [
    '--headless=new',
    `--remote-debugging-port=${dbgPort}`,
    `--user-data-dir=${profileDir}`,
    '--no-first-run', '--no-default-browser-check',
    '--disable-features=DialMediaRouteProvider',
    // 防 headless 后台节流：游戏 tab 的 wasm 洗牌/揭示异步流依赖定时器，
    // 被节流会让服务器 45s 洗牌超时把玩家踢出桌面（手牌作废）。
    '--disable-background-timer-throttling',
    '--disable-backgrounding-occluded-windows',
    '--disable-renderer-backgrounding',
    `--load-extension=${EXT_PATH}`,
    'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  chrome.stderr.on('data', (d) => {
    const s = String(d);
    if (s.includes('ERROR') || s.includes('error')) progress(`[chrome] ${s.trim().slice(0, 200)}`);
  });
  const cleanup = () => {
    if (process.env.KEEP_CHROME === '1') return;
    try { chrome.kill('SIGKILL'); } catch { /* ignore */ }
  };
  process.on('exit', cleanup);
  process.on('SIGINT', () => { cleanup(); process.exit(130); });

  const devtools = `http://127.0.0.1:${dbgPort}`;
  let version = null;
  for (let i = 0; i < 100; i++) {
    try { version = await (await fetch(`${devtools}/json/version`)).json(); break; } catch { await sleep(300); }
  }
  if (!version) throw new Error('DevTools 不可达');
  progress(`chrome ${version.Browser} ready`);

  let extId = null;
  for (let i = 0; i < 60; i++) {
    const targets = await (await fetch(`${devtools}/json/list`)).json();
    const sw = targets.find((t) => t.type === 'service_worker' && t.url.includes('/background/service_worker.js'));
    if (sw) { extId = new URL(sw.url).host; break; }
    await sleep(500);
  }
  if (!extId) throw new Error('扩展 service worker 未出现（加载失败？）');
  progress(`extension id: ${extId}`);
  await sleep(1200);

  // ===== 1. popup：一键创建钱包 =====
  const popupTarget = await newTarget(devtools, `chrome-extension://${extId}/popup/popup.html`);
  let popup = await connectCdp(popupTarget, 'popup');
  await sleep(800);
  const welcome = await waitForExpr(popup, `!!document.getElementById('welcome-create-btn')`, 15_000);
  if (welcome) {
    await popup.eval(`document.getElementById('welcome-create-btn').click()`);
    const pw = await waitForExpr(popup, `(() => {
      const n = document.getElementById('welcome-generated-password');
      return n && n.textContent.length >= 20 ? n.textContent : null;
    })()`, 30_000);
    if (!pw) throw new Error('一键创建钱包失败（无自动口令）');
    const pwFile = path.join(RUN_DIR, 'wallet_password.txt');
    writeFileSync(pwFile, pw);
    progress(`wallet created, password saved → ${pwFile} (${pw.length} chars)`);
    await popup.eval(`document.getElementById('welcome-done-btn').click()`);
    await sleep(1000);
  } else {
    progress('popup 已有钱包（无欢迎页），尝试解锁…');
    const needUnlock = await waitForExpr(popup, `!!document.getElementById('home-unlock-btn')`, 5_000);
    if (needUnlock) {
      const saved = existsSync(path.join(RUN_DIR, 'wallet_password.txt'))
        ? readFileSync(path.join(RUN_DIR, 'wallet_password.txt'), 'utf8').trim()
        : '';
      await popup.eval(`(() => {
        const n = document.getElementById('home-unlock-pw');
        n.value = ${JSON.stringify(saved)};
        n.dispatchEvent(new Event('input', { bubbles: true }));
        return true;
      })()`);
      await popup.eval(`document.getElementById('home-unlock-btn').click()`);
      await sleep(1500);
    }
  }

  // ===== 2. 水龙头铸造 PLAY note（签名输入）=====
  const faucet = await popupSend(popup, { type: 'popup:faucet', amount: 1000 }, 30_000);
  progress(`faucet mint: ${JSON.stringify(faucet)?.slice(0, 200)}`);
  const overview = await popupSend(popup, { type: 'popup:overview' }, 10_000);
  progress(`overview: onboarded=${overview?.onboarded} zchain=${JSON.stringify(overview?.layers?.zchain)}`);

  // ===== 3. poker 客户端：登录 =====
  const gameTarget = await newTarget(devtools, POKER_URL);
  let game = await connectCdp(gameTarget, 'game');
  // 桌面 UI 要求横屏（竖屏会盖 "Rotate your device" 遮罩）
  await game.send('Emulation.setDeviceMetricsOverride', {
    width: 1280, height: 720, deviceScaleFactor: 1, mobile: false,
  }).catch(() => { });
  await game.send('Page.bringToFront').catch(() => { });
  progress(`game tab opened: ${POKER_URL}`);
  await sleep(3000);
  // alert 会阻塞页面（隐藏真实报错）：改记入 window.__alerts
  await game.eval(`(() => {
    window.__alerts = [];
    window.alert = (m) => { window.__alerts.push(String(m)); };
    window.addEventListener('unhandledrejection', (e) => window.__alerts.push('unhandled: ' + String(e.reason?.message ?? e.reason)));
    return true;
  })()`);

  // 等待 React 渲染出登录按钮（Sign In / Log In / 登录）；先关 cookie 横幅
  const loginBtn = await waitForExpr(game, `(() => {
    const btns = [...document.querySelectorAll('button')];
    if (/cookies to ensure/i.test(document.body.innerText)) {
      const ok = btns.find((x) => /^OK$/.test(x.textContent.trim()));
      if (ok) ok.click();
    }
    const b = btns.find((x) => /^(Sign In|Log In|登录)$/.test(x.textContent.trim()));
    return b ? true : null;
  })()`, 60_000);
  if (!loginBtn) {
    await screenshot(game, 'no-login-button');
    throw new Error('poker 页面未渲染出登录按钮');
  }

  const alreadyLoggedIn = async () => game.eval(`(() => {
    const t = document.body.innerText;
    return (t.includes('Log Out') || t.includes('退出')) || (localStorage.getItem('token') ? true : null) || null;
  })()`, 5_000).catch(() => null);

  if (!(await alreadyLoggedIn())) {
    await game.eval(`(() => {
      const btns = [...document.querySelectorAll('button')];
      const b = btns.find((x) => /^(Sign In|Log In|登录)$/.test(x.textContent.trim()));
      b.click(); return true;
    })()`);
    await sleep(1200);
    const zchainBtn = await waitForExpr(game, `!!document.querySelector('[data-testid=login-zchain]')`, 15_000);
    if (!zchainBtn) {
      await screenshot(game, 'no-zchain-button');
      throw new Error('登录弹窗未出现 ZChain Wallet 按钮（扩展未注入 window.zchain？）');
    }
    await game.eval(`document.querySelector('[data-testid=login-zchain]').click()`);
    progress('ZChain Wallet 登录：等待扩展审批（连接 + 登录签名）…');
    for (let i = 0; i < 30; i++) {
      await drainApprovals(popup, 'login', 5);
      await sleep(1500);
      if (await alreadyLoggedIn()) break;
    }
    if (!(await alreadyLoggedIn())) {
      const alerts = await game.eval('JSON.stringify(window.__alerts ?? [])', 5_000).catch(() => '[]');
      const diag = await game.eval(`JSON.stringify({provider: !!window.zchain, zaddr: (localStorage.getItem('zchainAddress') ?? '').length, token: !!localStorage.getItem('token')})`, 5_000).catch(() => '?');
      await screenshot(game, 'login-stuck');
      throw new Error(`ZChain 钱包登录未完成（token 未落）alerts=${alerts} diag=${diag}`);
    }
  }
  progress('登录完成 ✓');

  // ===== 4. 入座（/play → Sit Down → 买入弹窗）=====
  await game.eval(`(() => { location.href = ${JSON.stringify(POKER_URL + '/play')}; return true; })()`);
  await sleep(4000);
  const sitBtn = await waitForExpr(game, `(() => {
    const btns = [...document.querySelectorAll('button')];
    const b = btns.find((x) => /^(Sit Down|入座)$/.test(x.textContent.trim()));
    return b ? true : null;
  })()`, 60_000);
  if (!sitBtn) {
    const seated = await waitForExpr(game, `document.body.innerText.includes('Fold') || document.body.innerText.includes('Check') ? true : null`, 3000);
    if (!seated) {
      await screenshot(game, 'no-sitdown');
      throw new Error('桌面未渲染出入座按钮');
    }
    progress('已在座（无空位按钮），跳过入座');
  } else {
    // 点击指定座位（SEAT 从 0 计）；找不到就点第一个空位
    const clicked = await game.eval(`(() => {
      const btns = [...document.querySelectorAll('button')].filter((x) => /^(Sit Down|入座)$/.test(x.textContent.trim()));
      const b = btns[${Math.min(SEAT, 8)}] ?? btns[0];
      if (!b) return null;
      b.click(); return btns.length;
    })()`);
    progress(`Sit Down clicked (空位数=${clicked})`);
    const amountInput = await waitForExpr(game, `!!document.getElementById('amount')`, 15_000);
    if (!amountInput) {
      await screenshot(game, 'no-buyin-modal');
      throw new Error('买入弹窗未出现');
    }
    await game.eval(`(() => {
      const n = document.getElementById('amount');
      n.value = '${BUYIN}';
      n.dispatchEvent(new Event('input', { bubbles: true }));
      return true;
    })()`);
    await sleep(300);
    await game.eval(`(() => {
      const form = document.getElementById('amount')?.closest('form');
      const submit = form?.querySelector('button[type=submit]');
      if (!submit) throw new Error('no submit button');
      submit.click();
      return true;
    })()`);
    progress(`买入提交（amount=${BUYIN}）：等待 buy_in 签名审批…`);
    await drainApprovals(popup, 'buyin', 10);
    await sleep(3000);
    await drainApprovals(popup, 'buyin2', 10);
    await screenshot(game, 'after-sitdown');
  }

  // ===== 5. 自动跟牌 + 等待手数 =====
  const deadline = startedAt + TIMEOUT_SECS * 1000;
  let lastCount = -1;
  let lastLogAt = 0;
  let stallSince = Date.now();
  while (Date.now() < deadline) {
    // 审批任何待定签名（保险）
    await drainApprovals(popup, 'loop', 3).catch(() => { });

    // 页面被弹回首页等非桌面场景：导航回 /play
    const onPlay = await game.eval(`location.pathname === '/play' ? 'yes' : 'no'`, 5_000).catch(() => 'unknown');
    if (onPlay === 'no') {
      progress('[nav] 不在 /play，跳回桌面…');
      await game.eval(`(() => { location.href = ${JSON.stringify(POKER_URL + '/play')}; return true; })()`).catch(() => { });
      await sleep(4000);
      await game.send('Emulation.setDeviceMetricsOverride', {
        width: 1280, height: 720, deviceScaleFactor: 1, mobile: false,
      }).catch(() => { });
      await game.send('Page.bringToFront').catch(() => { });
    }

    // bust 离座后自动重新入座：先查服务器座位表确认自己不在座
    const seatedNow = await game.eval(`fetch('/api/tables/1').then((r) => r.json()).then((d) => {
      const me = (localStorage.getItem('zchainAddress') || '').toLowerCase();
      return Object.values(d.players || {}).some((w) => String(w || '').toLowerCase() === me) ? 'seated' : 'out';
    }).catch(() => 'unknown')`, 10_000).catch(() => 'unknown');
    if (seatedNow === 'out') {
      const clicked = await game.eval(`(() => {
        if (document.getElementById('amount')) return null; // 买入弹窗已在流程中
        const btns = [...document.querySelectorAll('button')].filter((x) => /^(Sit Down|入座)$/.test(x.textContent.trim()));
        if (btns.length === 0) return null;
        btns[btns.length > 4 ? Math.min(${SEAT}, btns.length - 1) : 0].click();
        return btns.length;
      })()`, 10_000).catch(() => null);
      if (clicked) {
        progress(`[reseat] 不在座 → 点击 Sit Down（空位=${clicked}），走完整买入签名…`);
        // 买入签名消耗 note：重入座前先补水龙头，避免 NoPlayableNote
        await popupSend(popup, { type: 'popup:faucet', amount: 1000 }, 30_000)
          .then((r) => progress(`[reseat] faucet top-up: ${JSON.stringify(r)?.slice(0, 80)}`))
          .catch((e) => progress(`[reseat] faucet failed: ${e.message}`));
        const hasAmount = await waitForExpr(game, `!!document.getElementById('amount')`, 10_000);
        if (hasAmount) {
          await game.eval(`(() => {
            const n = document.getElementById('amount');
            n.value = '${BUYIN}';
            n.dispatchEvent(new Event('input', { bubbles: true }));
            return true;
          })()`);
          await sleep(300);
          await game.eval(`(() => {
            const form = document.getElementById('amount')?.closest('form');
            form?.querySelector('button[type=submit]')?.click();
            return true;
          })()`);
          await drainApprovals(popup, 'reseat-buyin', 10);
          await sleep(2000);
          await drainApprovals(popup, 'reseat-buyin2', 10);
        }
      }
    }

    // 自动跟牌：Check 优先 → Call → Fold
    const acted = await game.eval(`(() => {
      const find = (re) => [...document.querySelectorAll('button')].find((x) => !x.disabled && re.test(x.textContent.trim()));
      const b = find(/^(Check|过)$/) || find(/^(Call( \\d+[\\d,.]*)?|跟注.*|跟.*)$/) || find(/^(Fold|弃牌)$/) || find(/Check/);
      if (!b) return null;
      b.click();
      return b.textContent.trim();
    })()`, 10_000).catch(() => null);
    if (acted) progress(`[autoplay] clicked: ${acted}`);

    const count = await anchoredCount();
    if (count !== lastCount) {
      progress(`[progress] anchored=${count}/${TARGET_HANDS}`);
      lastCount = count;
      stallSince = Date.now();
    }
    if (count >= TARGET_HANDS) {
      progress(`DONE: ${count} anchored settlements ≥ target ${TARGET_HANDS}`);
      await screenshot(game, 'final');
      // ===== 区块链浏览器验收：extension Proof Portal 拉取结算并本地验证 =====
      const portalOk = await verifyOnPortal(devtools, extId);
      return portalOk ? 0 : 1;
    }
    // 卡死监测：15 分钟无新手且无动作可点 → 截图报障（不退出，交 watchdog）
    if (Date.now() - stallSince > 15 * 60 * 1000 && Date.now() - lastLogAt > 15 * 60 * 1000) {
      lastLogAt = Date.now();
      await screenshot(game, 'stall');
      progress(`[warn] 15min no progress (hands=${count})`);
    }
    await sleep(1500);
  }
  progress(`TIMEOUT: anchored=${lastCount}/${TARGET_HANDS}`);
  return 1;
}

main()
  .then((code) => process.exit(code))
  .catch((e) => {
    progress(`FATAL: ${e.message}`);
    process.exit(1);
  });
