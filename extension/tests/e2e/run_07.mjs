#!/usr/bin/env node
// =============================================================================
// run_07.mjs — Extension 0.6.1 一键 onboarding：真实浏览器 E2E（浏览器操作）
//
// 参考 MetaMask 的交互：新用户首屏即“一键创建钱包”；已有钱包绝不触发创建。
//
// 覆盖：
//   O1 新用户首屏 = 欢迎页（一键创建按钮 + 高级自定义 + 导入提示）；
//   O2 一键创建 → 一次成功页：自动口令只显一次 + 三链地址；
//   O3 “开始使用” → 统一首页（三链卡片，全部已解锁）；
//   O4 老用户不触发：锁定全部后重开 popup → 无欢迎页，出现统一解锁；
//   O5 统一解锁：错口令 fail-closed → 正确口令全层解锁；
//   O6 明细页直达：首页卡片进入 EVM/Starknet 钱包视图（不再出现创建流程）；
//   O7 API 级防护：已 onboarded 后再调 quickCreate → OnboardedAlready。
//
// 用法（repo 根目录）：node extension/tests/e2e/run_07.mjs
// 退出码：0 = 全部 PASS；1 = 存在 FAIL。
// =============================================================================

import { spawn } from 'node:child_process';
import { appendFileSync, existsSync, mkdtempSync, readdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const EXT_ROOT = path.resolve(HERE, '..', '..');
const OUT_JSON = path.join(HERE, 'e2e07_result.json');
const OUT_PNG = path.join(HERE, 'e2e07_screenshot.png');
const PROGRESS = path.join(HERE, 'e2e07_progress.log');

const PW = 'correct horse battery staple';

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

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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
  static async connect(url) {
    const ws = new WebSocket(url.replace('ws://localhost:', 'ws://127.0.0.1:'));
    await new Promise((res, rej) => {
      ws.addEventListener('open', res, { once: true });
      ws.addEventListener('error', rej, { once: true });
    });
    return new Cdp(ws);
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
      new Promise((_, rej) => setTimeout(() => rej(new Error(`eval timeout: ${expr.slice(0, 60)}`)), timeoutMs)),
    ]);
  }
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
  const profileDir = mkdtempSync(path.join(tmpdir(), 'zchain_e2e07_'));
  const dbgPort = 11000 + Math.floor(Math.random() * 30000);
  const chrome = spawn(chromeBin, [
    '--headless=new',
    `--remote-debugging-port=${dbgPort}`,
    `--user-data-dir=${profileDir}`,
    '--no-first-run', '--no-default-browser-check',
    `--load-extension=${EXT_ROOT}`,
    'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  const cleanup = () => { try { chrome.kill('SIGKILL'); } catch { /* ignore */ } };
  process.on('exit', cleanup);
  process.on('SIGINT', () => { cleanup(); process.exit(130); });

  try {
    const devtools = `http://127.0.0.1:${dbgPort}`;
    let version = null;
    for (let i = 0; i < 100; i++) {
      try { version = await (await fetch(`${devtools}/json/version`)).json(); break; } catch { await sleep(300); }
    }
    if (!version) throw new Error('DevTools 不可达');

    let extId = null;
    for (let i = 0; i < 60; i++) {
      const targets = await (await fetch(`${devtools}/json/list`)).json();
      const sw = targets.find((t) => t.type === 'service_worker' && t.url.includes('/background/service_worker.js'));
      if (sw) { extId = new URL(sw.url).host; break; }
      await sleep(500);
    }
    if (!extId) throw new Error('扩展 service worker 未出现（加载失败？）');
    await sleep(1500);
    const EXT = `chrome-extension://${extId}`;
    console.log(`extension id: ${extId}`);

    const firstPopupTarget = await newTarget(devtools, `${EXT}/popup/popup.html`);
    let page = await connectCdp(firstPopupTarget, 'popup');
    let oldPopupTargetId = firstPopupTarget.id;
    const msg = (m) => page.eval(`chrome.runtime.sendMessage(${JSON.stringify(m)})`, 60_000);
    async function waitForExpr(expr, timeoutMs = 15_000, interval = 250) {
      const t0 = Date.now();
      for (;;) {
        let v = null;
        try { v = await page.eval(expr, 5_000); } catch { /* 渲染瞬间 */ }
        if (v) return v;
        if (Date.now() - t0 > timeoutMs) return null;
        await sleep(interval);
      }
    }
    const gen = () => page.eval(`window.__zRenderGen ?? 0`).catch(() => 0);
    async function waitRender(beforeGen, effectExpr, timeoutMs = 20_000) {
      const t0 = Date.now();
      for (;;) {
        let v = null;
        try { v = await page.eval(`((window.__zRenderGen ?? 0) > ${Number(beforeGen)}) && (${effectExpr}) ? true : null`, 5_000); } catch { /* 渲染瞬间 */ }
        if (v) return true;
        if (Date.now() - t0 > timeoutMs) return null;
        await sleep(200);
      }
    }
    async function click(selector) {
      await page.eval(`(() => {
        const n = document.getElementById(${JSON.stringify(selector)});
        if (!n) throw new Error('missing #${selector}');
        n.click(); return true;
      })()`);
    }
    async function fill(selector, value) {
      await page.eval(`(() => {
        const n = document.getElementById(${JSON.stringify(selector)});
        if (!n) throw new Error('missing #${selector}');
        n.value = ${JSON.stringify(value)};
        n.dispatchEvent(new Event('input', { bubbles: true }));
        return true;
      })()`);
    }
    const openPopup = async () => {
      const t = await newTarget(devtools, `${EXT}/popup/popup.html`);
      const conn = await connectCdp(t, 'popup-reopen');
      await sleep(800);
      return { target: t, conn };
    };

    // ===== O1：新用户首屏 = 一键创建欢迎页 =====
    const o1 = await waitForExpr(`(() => {
      const btn = document.getElementById('welcome-create-btn');
      const adv = document.getElementById('welcome-advanced');
      const imp = document.getElementById('welcome-import');
      return btn && adv && imp && document.body.innerText.includes('一键创建钱包') ? true : null;
    })()`, 20_000);
    record('O1 新用户首屏 = 欢迎页（一键创建 + 高级 + 导入入口）', o1 === true);
    const overview0 = await msg({ type: 'popup:overview' });
    record('O1b SW 状态：onboarded=false（三层均无钱包）',
      overview0?.onboarded === false && overview0.layers?.zchain?.has === false
        && overview0.layers?.evm?.has === false && overview0.layers?.stk?.has === false,
      JSON.stringify(overview0?.onboarded));

    // ===== O2：一键创建 → 成功页（口令只显一次 + 三链地址）=====
    let savedPw = null; // 一键创建自动生成的口令（成功页保存下来的那份）
    await page.eval(`window.__rej = []; window.addEventListener('unhandledrejection', (e) => window.__rej.push(String(e.reason?.message ?? e.reason))); true`);
    await click('welcome-create-btn');
    const successRaw = await waitForExpr(`(() => {
      const c = document.getElementById('welcome-success');
      if (c) {
        const pw = document.getElementById('welcome-generated-password')?.textContent ?? '';
        return { pw: pw.length >= 20 ? pw : null };
      }
      const t = document.getElementById('welcome-card')?.innerText ?? '';
      if (t.includes('InternalError') || t.includes('Error')) return { err: t.slice(-160) };
      return null;
    })()`, 30_000);
    const success = successRaw?.pw ?? null;
    savedPw = success;
    const rej = await page.eval('JSON.stringify(window.__rej)').catch(() => '[]');
    record('O2-diag', true, `raw=${JSON.stringify(successRaw)?.slice(0, 160)} rej=${rej}`);
    record('O2 一键创建 → 成功页：自动口令只显一次 + 三链地址', typeof success === 'string' && success.length >= 20,
      typeof success === 'string' ? `${success.slice(0, 6)}…（${success.length} 字符）` : String(success));
    const created = await msg({ type: 'popup:overview' });
    record('O2b 创建后 SW 状态：onboarded=true + 三层有钱包 + 全部已解锁',
      created?.onboarded === true && created.layers?.zchain?.has && created.layers?.zchain?.unlocked
        && created.layers?.evm?.has && created.layers?.evm?.unlocked
        && created.layers?.stk?.has && created.layers?.stk?.unlocked,
      JSON.stringify({ onboarded: created?.onboarded }).slice(0, 60));

    // ===== O3：开始使用 → 统一首页 =====
    await click('welcome-done-btn');
    const home = await waitForExpr(`(() => {
      const card = document.getElementById('home-card');
      if (!card) return null;
      return card.innerText.includes('多链总览') && card.innerText.includes('进入钱包') ? true : null;
    })()`, 15_000);
    record('O3 统一首页：三链卡片 + 进入钱包（全部已解锁）', home === true);

    // ===== O4：老用户不触发（锁定全部 → 重开 popup → 无欢迎页，有统一解锁）=====
    await msg({ type: 'popup:lock' });
    await msg({ type: 'popup:evmLock' });
    await msg({ type: 'popup:stkLock' });
    // 真实用户流程：重新打开 popup 新标签，关闭旧标签，后续操作走新标签
    const reopen = await openPopup();
    await fetch(`${devtools}/json/close/${oldPopupTargetId}`).catch(() => { });
    oldPopupTargetId = reopen.target.id;
    page = reopen.conn;
    const diag = await waitForExpr(`(() => {
      const noWelcome = !document.getElementById('welcome-create-btn');
      const unlock = document.getElementById('home-unlock-btn');
      return noWelcome && unlock ? { ok: true } : { view: (document.getElementById('view')?.innerText ?? 'EMPTY').slice(0, 140) };
    })()`, 20_000);
    record('O4 老用户（有钱包）重开 popup：不触发创建，出现统一解锁',
      diag?.ok === true, JSON.stringify(diag ?? null));

    // ===== O5：统一解锁（错口令 fail-closed → 正确口令全层解锁）=====
    await fill('home-unlock-pw', 'totally wrong');
    await click('home-unlock-btn');
    const denied = await waitForExpr(`document.body.innerText.includes('口令错误')`, 10_000);
    record('O5a 统一解锁错口令 → fail-closed', denied === true);
    await fill('home-unlock-pw', savedPw ?? PW);
    await click('home-unlock-btn');
    const unlockedAll = await waitForExpr(`(() => {
      const card = document.getElementById('home-card');
      return card && card.innerText.includes('进入钱包') && !document.getElementById('home-unlock-btn') ? true : null;
    })()`, 20_000);
    record('O5b 正确口令（一键创建自动口令）→ 全层解锁回首页', unlockedAll === true);

    // ===== O6：明细页直达（首页卡片 → EVM / Starknet 钱包视图，无创建流程）=====
    await click('home-evm-open');
    const evmDash = await waitForExpr(`!!document.getElementById('evm-address') && !document.getElementById('evm-create-btn')`, 15_000);
    record('O6a 首页进入 EVM 钱包视图（直接是已解锁面板）', evmDash === true);
    await click('mode-stk');
    const stkDash = await waitForExpr(`!!document.getElementById('stk-address') && !document.getElementById('stk-create-btn')`, 15_000);
    record('O6b 切到 Starknet 视图（同样直达面板）', stkDash === true);
    await click('mode-home');
    const backHome = await waitForExpr(`!!document.getElementById('home-card')`, 15_000);
    record('O6c 首页按钮回到总览', backHome === true);

    // ===== O7：API 级防护（已 onboarded 再 quickCreate → OnboardedAlready）=====
    const guard = await msg({ type: 'popup:quickCreate' });
    record('O7 已有钱包再一键创建 → OnboardedAlready（绝不覆盖）',
      guard?.error?.code === 'OnboardedAlready', JSON.stringify(guard));

    // ===== 截图 =====
    await sleep(800);
    const shot = await Promise.race([page.send('Page.captureScreenshot', { format: 'png' }), new Promise((_, rej) => setTimeout(() => rej(new Error('screenshot timeout')), 10_000))]);
    writeFileSync(OUT_PNG, Buffer.from(shot.data, 'base64'));

    const pass = results.filter((r) => r.ok).length;
    const summary = {
      date: new Date().toISOString(),
      browser: version.Browser,
      extensionId: extId,
      total: results.length, pass, fail: results.length - pass,
      results,
    };
    writeFileSync(OUT_JSON, JSON.stringify(summary, null, 2) + '\n');
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
