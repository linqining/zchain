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
//   SEAT（默认 4） BUYIN（默认 1000） TIMEOUT_SECS（默认 43200）
//   STRATEGY（默认 random：随机边缘策略 raise/all-in/fold/call/check，
//     'passive' = 旧版 Check 优先跟牌）
//   TIMEOUT_PROBE（默认 0.015：轮到时以该概率故意延迟一轮，触发服务器
//     BETTING_TIMEOUT 自动代打路径）
//   CHROME_BIN（默认自动探测 /tmp/chrome） KEEP_CHROME=1（退出不杀浏览器）
// 边缘事件统计：$RUN_DIR/edge_stats.jsonl（raise/all-in/fold/reseat/bust…）。
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
const TIMEOUT_SECS = Number(process.env.TIMEOUT_SECS ?? 43200);
const STRATEGY = process.env.STRATEGY ?? 'random';
const TIMEOUT_PROBE = Number(process.env.TIMEOUT_PROBE ?? 0.015);
const RUN_DIR = process.env.POKER_AIR_RUN_DIR ?? '/tmp/poker-air-zchain';
const LOG = path.join(RUN_DIR, 'browser.log');
const EDGE_STATS = path.join(RUN_DIR, 'edge_stats.jsonl');

const edgeStat = (kind, detail = {}) => {
  try {
    appendFileSync(EDGE_STATS, JSON.stringify({ t: new Date().toISOString(), kind, ...detail }) + '\n');
  } catch { /* ignore */ }
  progress(`[edge] ${kind} ${JSON.stringify(detail).slice(0, 160)}`);
};

mkdirSync(RUN_DIR, { recursive: true });
const progress = (line) => {
  const text = `[${new Date().toISOString()}] ${line}`;
  try { appendFileSync(LOG, text + '\n'); } catch { /* ignore */ }
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
async function verifyOnPortal(devtools, extId, popupPage) {
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
    // SW 预热：长跑后扩展 SW 可能休眠/通道卡死，先在 popup 上 ping 通再开 portal。
    if (popupPage) {
      for (let i = 0; i < 3; i++) {
        try {
          await popupSend(popupPage, { type: 'popup:overview' }, 15_000);
          break;
        } catch (e) {
          progress(`[portal] SW ping ${i + 1} failed: ${e.message.slice(0, 80)}`);
          await sleep(2_000);
        }
      }
    }
    let portal = null;
    for (let attempt = 1; attempt <= 3; attempt++) {
      let portalTarget = null;
      try {
        portalTarget = await newTarget(devtools, `chrome-extension://${extId}/portal/portal.html`);
        portal = await connectCdp(portalTarget, 'portal', 20_000);
      } catch (e) {
        progress(`[portal] attempt ${attempt}: connect failed: ${e.message.slice(0, 100)}`);
        if (portalTarget) await closeTarget(devtools, portalTarget.id);
        portal = null;
        await sleep(3_000);
        continue;
      }
      const ready = await waitForExpr(portal, `!!document.getElementById('binding') && !!document.getElementById('verify')`, 20_000);
      if (!ready) {
        await screenshot(portal, 'portal-not-ready');
        progress(`[portal] attempt ${attempt}: 页面未就绪`);
        await closeTarget(devtools, portalTarget.id);
        try { portal.close(); } catch { /* ignore */ }
        portal = null;
        await sleep(3_000);
        continue;
      }
      // 等 init 完成（refreshHeader 把 gateway-line 从静态"加载中…"替换掉）
      const inited = await waitForExpr(portal, `(() => {
        const n = document.getElementById('gateway-line');
        return n && !n.innerText.includes('加载中') ? true : null;
      })()`, 20_000);
      if (!inited) {
        progress(`[portal] attempt ${attempt}: init 未完成（SW 消息通道挂起），重载重试`);
        await closeTarget(devtools, portalTarget.id);
        try { portal.close(); } catch { /* ignore */ }
        portal = null;
        await sleep(3_000);
        continue;
      }
      break;
    }
    if (!portal) {
      await screenshot(portal, 'portal-not-ready');
      progress('[portal] FAIL: portal 页面多次重试仍未就绪');
      return false;
    }
    const gatewayLine = await portal.eval(`document.getElementById('gateway-line')?.innerText ?? ''`, 5_000);
    progress(`[portal] 打开区块链浏览器（${gatewayLine.slice(0, 80)}），binding=${binding.slice(0, 16)}…`);
    // 注意：verify 点击后结算关系复验 + STARK wasm 验证可能耗时较长（wasm
    // 首次编译 + FRI 全量验证），重试点击会打断进行中的验证——结算明细
    // 出来后只能等待，不能重按。
    let ok = false;
    for (let attempt = 1; attempt <= 3 && !ok; attempt++) {
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
        progress(`[portal] attempt ${attempt}: 结算明细未渲染 err=${err.slice(0, 160)}`);
        if (attempt < 3) await sleep(3_000);
        continue;
      }
      const detail = await portal.eval(`document.getElementById('settlement-body')?.innerText ?? ''`, 5_000);
      progress(`[portal] ✓ 区块链浏览器已展示结算明细（${detail.split('\n').slice(0, 4).join(' | ').slice(0, 200)}）`);
      // wasm 验证链（本地复验 + 可选 STARK）——等待 verdict / conclusion / err
      // 任意一个落地（240s 上限覆盖慢机器上的 wasm 编译 + 验证）。
      const landed = await waitForExpr(portal, `(() => {
        const v = document.getElementById('verdict-body');
        if (v && v.innerText.length > 0) return 'verdict';
        const c = document.getElementById('conclusion-card');
        if (c && c.style.display !== 'none' && (c.innerText?.length ?? 0) > 20) return 'conclusion';
        const e = document.getElementById('err');
        if (e && e.innerText.length > 0) return 'err:' + e.innerText.slice(0, 200);
        return null;
      })()`, 240_000);
      if (!landed) {
        progress('[portal] wasm 验证链 240s 未落地');
        await screenshot(portal, 'portal-hang');
        continue;
      }
      if (String(landed).startsWith('err:')) {
        progress(`[portal] FAIL: ${String(landed).slice(0, 220)}`);
        await screenshot(portal, 'portal-fail');
        return false;
      }
      ok = true;
    }
    if (!ok) {
      await screenshot(portal, 'portal-fail');
      progress('[portal] FAIL: 结算明细/验证结论未渲染');
      return false;
    }
    const verdict = await portal.eval(`(() => {
      const v = document.getElementById('verdict-body');
      if (v && v.innerText.length > 0) return v.innerText.slice(0, 300);
      const c = document.getElementById('conclusion-card');
      return c && c.style.display !== 'none' ? (c.innerText ?? '').slice(0, 300) : '';
    })()`, 5_000).catch(() => '');
    progress(`[portal] 本地验证结论: ${String(verdict).replace(/\n/g, ' | ').slice(0, 260)}`);
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
  // 口令文件在启动流程（一键创建钱包）中才落盘——必须惰性读取，
  // 启动时读只会得到空串，自动锁后就永远无法解锁。
  const readWalletPw = () => existsSync(path.join(RUN_DIR, 'wallet_password.txt'))
    ? readFileSync(path.join(RUN_DIR, 'wallet_password.txt'), 'utf8').trim()
    : '';
  const chromeBin = findChrome();
  const profileDir = mkdtempSync(path.join(tmpdir(), 'poker_air_chrome_'));
  const dbgPort = Number(process.env.DEBUG_PORT ?? (11000 + Math.floor(Math.random() * 30000)));
  progress(`chrome=${chromeBin} profile=${profileDir} debug=${dbgPort}`);
  const chrome = spawn(chromeBin, [
    '--headless=new',
    // 本机 GUI 会话状态变化会让 GPU helper 进程反复崩溃（"GPU process
    // isn't usable. Goodbye."）拖死整个浏览器；GPU 内嵌进浏览器进程绕开。
    '--in-process-gpu',
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
  // 扩展 popup 页偶发加载失败（今天环境里子进程不稳定）：关掉重来，最多 4 次。
  let popup = null;
  let popupTargetId = null;
  const revivePopup = async (reason) => {
    if (popupTargetId) await closeTarget(devtools, popupTargetId).catch(() => { });
    popupTargetId = null;
    for (let i = 0; i < 3; i++) {
      try {
        const t = await newTarget(devtools, `chrome-extension://${extId}/popup/popup.html`);
        const p = await connectCdp(t, 'popup', 20_000);
        popupTargetId = t.id;
        await sleep(600);
        progress(`[popup] 连接已重建（${reason}，第 ${i + 1} 次）`);
        return p;
      } catch (e) {
        progress(`[popup] revive ${i + 1} failed: ${e.message.slice(0, 90)}`);
        await sleep(2_000);
      }
    }
    return null;
  };
  for (let i = 0; i < 4 && !popup; i++) {
    const popupTarget = await newTarget(devtools, `chrome-extension://${extId}/popup/popup.html`);
    try {
      popup = await connectCdp(popupTarget, 'popup', 25_000);
      popupTargetId = popupTarget.id;
    } catch (e) {
      progress(`[popup] connect attempt ${i + 1} failed: ${e.message}`);
      await closeTarget(devtools, popupTarget.id);
      popup = null;
      await sleep(3_000);
    }
  }
  if (!popup) throw new Error('popup CDP 连接失败（4 次重试）');
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

  // 等待 React 渲染出登录按钮（Sign In / Log In / 登录）；先关 cookie 横幅。
  // vite 冷启动首访变换模块图可慢至 ~1 分钟，等待窗口放宽到 180s。
  const loginBtn = await waitForExpr(game, `(() => {
    const btns = [...document.querySelectorAll('button')];
    if (/cookies to ensure/i.test(document.body.innerText)) {
      const ok = btns.find((x) => /^OK$/.test(x.textContent.trim()));
      if (ok) ok.click();
    }
    const b = btns.find((x) => /^(Sign In|Log In|登录)$/.test(x.textContent.trim()));
    return b ? true : null;
  })()`, 180_000);
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
  })()`, 120_000);
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
  // v2：单次 eval 快速路径（按钮探测 + 随机策略 + 点击一气呵成），重活
  // （审批/导航/重入座/进度）降频到慢路径，把每手下注决策延迟从 ~5.5s
  // 压到 <1s。随机策略覆盖 fold / bet / raise / all-in（服务器 bot 只会
  // call/check，边缘场景全靠人类位驱动）。
  const ACTION_SCRIPT = `(() => {
    const now = Date.now();
    if (window.__lastActAt && now - window.__lastActAt < 800) return { acted: 'cooldown' };
    const btns = [...document.querySelectorAll('button')].filter((b) => !b.disabled);
    const find = (re) => btns.find((b) => re.test(b.textContent.trim()));
    const check = find(/^(Check|过牌)$/);
    const call = find(/^(Call|跟注)/);
    const fold = find(/^(Fold|弃牌)$/);
    const betBtn = find(/^(Bet|下注)/);
    const allin = find(/^(All In|全押)/);
    if (!check && !call && !fold) return { acted: null };
    const mark = () => { window.__lastActAt = Date.now(); };
    const click = (b) => { mark(); b.click(); return true; };
    const PROBE = ${Number.isFinite(TIMEOUT_PROBE) ? TIMEOUT_PROBE : 0};
    if (PROBE > 0 && Math.random() < PROBE) return { acted: 'probe-wait' };
    const r = Math.random();
    // 上面 find 的 call/compare：check 可用 = 无人下注（免费巡圈）
    if (check) {
      if (r < 0.58) return { acted: 'check', ok: click(check) };
      if (r < 0.82 && betBtn) {
        const s = document.querySelector('input[type=range]');
        if (!s) return { acted: 'check', ok: click(check) };
        const mn = Number(s.min) || 0, mx = Number(s.max) || 0;
        if (mx <= mn) return { acted: 'check', ok: click(check) };
        const size = r < 0.66 ? mn : r < 0.90 ? mn * 2 : mx * 0.75;
        const v = Math.max(mn, Math.min(mx, Math.round(size / 10) * 10));
        const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
        setter.call(s, String(v));
        s.dispatchEvent(new Event('input', { bubbles: true }));
        mark();
        setTimeout(() => {
          const b = [...document.querySelectorAll('button')].find((x) => /^(Bet|下注)/.test(x.textContent.trim()) && !x.disabled);
          if (b) b.click();
        }, 400);
        return { acted: 'bet', amount: v };
      }
      if (r < 0.90 && allin) return { acted: 'allin', ok: click(allin) };
      if (fold) return { acted: 'fold', ok: click(fold) };
      return { acted: 'check', ok: click(check) };
    }
    // 面对下注
    if (r < 0.52 && call) return { acted: 'call', ok: click(call) };
    if (r < 0.74 && fold) return { acted: 'fold', ok: click(fold) };
    if (r < 0.92 && betBtn) {
      const s = document.querySelector('input[type=range]');
      if (!s) return call ? { acted: 'call', ok: click(call) } : { acted: null };
      const mn = Number(s.min) || 0, mx = Number(s.max) || 0;
      if (mx <= mn) return call ? { acted: 'call', ok: click(call) } : (allin ? { acted: 'allin', ok: click(allin) } : { acted: null });
      const size = r < 0.78 ? mn : mx * 0.6;
      const v = Math.max(mn, Math.min(mx, Math.round(size / 10) * 10));
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      setter.call(s, String(v));
      s.dispatchEvent(new Event('input', { bubbles: true }));
      mark();
      setTimeout(() => {
        const b = [...document.querySelectorAll('button')].find((x) => /^(Bet|下注)/.test(x.textContent.trim()) && !x.disabled);
        if (b) b.click();
      }, 400);
      return { acted: 'raise', amount: v };
    }
    if (allin) return { acted: 'allin', ok: click(allin) };
    if (call) return { acted: 'call', ok: click(call) };
    if (fold) return { acted: 'fold', ok: click(fold) };
    return { acted: null };
  })()`;

  const deadline = startedAt + TIMEOUT_SECS * 1000;
  const actTotals = { check: 0, call: 0, fold: 0, bet: 0, raise: 0, allin: 0, probe: 0 };
  // 钱包扩展有 idle 自动锁（安全设计）：锁后水龙头/买入签名全部
  // SessionInvalid，玩家从此无法回座（实测会退化成 bots 单独打牌）。
  // 自动化在慢路径轮询锁态，锁了就用保存口令重解锁——等价真人输口令。
  // 锁态权威字段 = overview.layers.zchain.unlocked（顶层无 unlocked 字段）；
  // popup 页连接死亡时自动重建（重开标签页）再操作。
  let unlockFailStreak = 0;
  const ensureUnlocked = async () => {
    let st = null;
    try {
      st = await popupSend(popup, { type: 'popup:overview' }, 8_000);
    } catch { /* popup 页可能已死，走重建 */ }
    if (!st) {
      const revived = await revivePopup('ensureUnlocked');
      if (!revived) {
        progress('[wallet] popup 连接重建失败，本轮跳过解锁');
        return false;
      }
      popup = revived;
      try {
        st = await popupSend(popup, { type: 'popup:overview' }, 8_000);
      } catch { return false; }
    }
    if (st?.layers?.zchain?.unlocked) return true;
    const WALLET_PW = readWalletPw();
    if (!WALLET_PW) {
      progress('[wallet] 钱包为锁态且无保存口令，无法自动解锁');
      return false;
    }
    // 优先直接发 quickUnlock 消息（popup 页 UI 不会随锁态自动重绘，
    // DOM 表单路径在长跑里不可靠——实测"解锁表单未渲染"）。
    let res = null;
    try {
      res = await popupSend(popup, { type: 'popup:quickUnlock', password: WALLET_PW }, 15_000);
    } catch { /* popup 页死，走重建后重试 */ }
    if (!res) {
      const revived = await revivePopup('quickUnlock');
      if (revived) {
        popup = revived;
        try {
          res = await popupSend(popup, { type: 'popup:quickUnlock', password: WALLET_PW }, 15_000);
        } catch { /* ignore */ }
      }
    }
    await sleep(1_000);
    const st2 = await popupSend(popup, { type: 'popup:overview' }, 8_000).catch(() => null);
    if (st2?.layers?.zchain?.unlocked) {
      progress('[wallet] 自动锁已触发 → 用保存口令重新解锁 ✓');
      unlockFailStreak = 0;
      return true;
    }
    unlockFailStreak++;
    progress(`[wallet] 解锁尝试后仍为锁态（连续 ${unlockFailStreak} 次，res=${JSON.stringify(res)?.slice(0, 120) ?? 'null'}）`);
    // 连续失败 → SW 会话/keystore 状态僵死，退出换全新实例（监督者会用
    // 新 chrome profile 建新钱包并同步口令文件）。
    if (unlockFailStreak >= 3) {
      progress('[wallet] FATAL-unlock: 连续 3 次解锁失败 → 退出换新浏览器实例');
      process.exit(2);
    }
    return false;
  };
  let iter = 0;
  let lastCount = -1;
  let lastLogAt = 0;
  let stallSince = Date.now();
  let lastMaintenance = 0;
  let lastReseatAt = 0;
  let reseatStall = 0;
  // CDP 连续失败看门狗：Chrome 挂死/崩溃时 game.eval 永远静默失败，
  // 死循环不退出会让 supervisor 永远等不到重启。连续失败超过阈值即抛出
  // 退出（非 0），由 supervisor 清理 Chrome 残留并拉起全新浏览器。
  let cdpFailStreak = 0;
  const CDP_FAIL_LIMIT = 8;
  while (Date.now() < deadline) {
    iter++;
    const res = await game.eval(ACTION_SCRIPT, 8_000).catch(() => null);
    if (res === null) {
      cdpFailStreak++;
      if (cdpFailStreak >= CDP_FAIL_LIMIT) {
        throw new Error(`CDP 连续失败 ${cdpFailStreak} 次（Chrome 挂死/崩溃），退出以触发 supervisor 重启`);
      }
    } else {
      cdpFailStreak = 0;
    }
    const acted = res?.acted ?? null;
    if (acted && acted !== 'cooldown' && acted !== 'probe-wait' && acted !== null) {
      const key = acted === 'bet' ? 'bet' : acted === 'probe-wait' ? 'probe' : acted;
      if (key in actTotals) actTotals[key]++;
      if (['fold', 'raise', 'allin', 'bet'].includes(acted)) {
        edgeStat(acted, { amount: res.amount ?? null });
      }
      if (acted === 'probe-wait') {
        edgeStat('timeout-probe', {});
        await sleep(9_000); // 故意错过一轮，触发服务器 BETTING_TIMEOUT 代打
      } else {
        await sleep(700);
      }
      stallSince = Date.now();
    } else if (acted === 'probe-wait') {
      edgeStat('timeout-probe', {});
      await sleep(9_000); // 故意错过一轮，触发服务器 BETTING_TIMEOUT 代打
    } else {
      // 慢路径：每 ~4s 做一次重活（审批/锁态/导航/重入座/座位检查）
      if (Date.now() - lastMaintenance > 4_000) {
        lastMaintenance = Date.now();
        await drainApprovals(popup, 'loop', 3).catch(() => { });
        await ensureUnlocked();

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
        if (seatedNow === 'out' && Date.now() - lastReseatAt > 8_000) {
          lastReseatAt = Date.now();
          edgeStat('bust-reseat-begin', {});
          const clicked = await game.eval(`(() => {
            // 买入弹窗已开（上次 reseat 流程中断残留）：不再跳过——返回 'modal'
            // 让下方流程继续走 补水→填额→提交→审批，否则弹窗永久卡死重入座。
            if (document.getElementById('amount')) return 'modal';
            const btns = [...document.querySelectorAll('button')].filter((x) => /^(Sit Down|入座)$/.test(x.textContent.trim()));
            if (btns.length === 0) return null;
            btns[btns.length > 4 ? Math.min(${SEAT}, btns.length - 1) : 0].click();
            return btns.length;
          })()`, 10_000).catch(() => null);
          if (clicked) {
            if (clicked !== 'modal') {
              progress(`[reseat] 不在座 → 点击 Sit Down（空位=${clicked}），走完整买入签名…`);
            }
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
              // 只有服务器确认入座才算成功；失败让下轮节流后重试
              const seatedAfter = await game.eval(`fetch('/api/tables/1').then((r) => r.json()).then((d) => {
                const me = (localStorage.getItem('zchainAddress') || '').toLowerCase();
                return Object.values(d.players || {}).some((w) => String(w || '').toLowerCase() === me) ? 'seated' : 'out';
              }).catch(() => 'unknown')`, 10_000).catch(() => 'unknown');
              if (seatedAfter === 'seated') {
                edgeStat('bust-reseat-done', {});
                reseatStall = 0;
              } else {
                edgeStat('bust-reseat-miss', {});
              }
            }
          } else if (clicked === null) {
            // 页面上既无 Sit Down 按钮也无买入弹窗：服务器重启后客户端
            // 缓存的旧 table（closed=true）会让 join effect 永久跳过重新
            // 加入 → 只能整页刷新恢复初始态，刷新后下一轮即可点 Sit Down。
            reseatStall++;
            progress(`[reseat] 桌面无可用入座按钮（stall=${reseatStall}）`);
            if (reseatStall >= 3) {
              reseatStall = 0;
              progress('[reseat] 整页刷新以清除陈旧 table 状态…');
              await game.eval(`location.reload(); true`).catch(() => { });
              await sleep(6000);
            }
          }
        }
      }
      await sleep(450);
    }

    const count = await anchoredCount();
    if (count !== lastCount) {
      progress(`[progress] anchored=${count}/${TARGET_HANDS} acts=${JSON.stringify(actTotals)}`);
      lastCount = count;
      stallSince = Date.now();
    }
    if (count >= TARGET_HANDS) {
      progress(`DONE: ${count} anchored settlements ≥ target ${TARGET_HANDS}`);
      progress(`[summary] action totals: ${JSON.stringify(actTotals)}`);
      await screenshot(game, 'final');
      // ===== 区块链浏览器验收：extension Proof Portal 拉取结算并本地验证 =====
      const portalOk = await verifyOnPortal(devtools, extId, popup);
      return portalOk ? 0 : 1;
    }
    // 卡死监测：15 分钟无新手且无动作可点 → 截图报障（不退出，交 watchdog）
    if (Date.now() - stallSince > 15 * 60 * 1000 && Date.now() - lastLogAt > 15 * 60 * 1000) {
      lastLogAt = Date.now();
      await screenshot(game, 'stall');
      progress(`[warn] 15min no progress (hands=${count})`);
    }
  }
  progress(`TIMEOUT: anchored=${lastCount}/${TARGET_HANDS}`);
  progress(`[summary] action totals: ${JSON.stringify(actTotals)}`);
  return 1;
}

main()
  .then((code) => process.exit(code))
  .catch((e) => {
    progress(`FATAL: ${e.message}`);
    process.exit(1);
  });
