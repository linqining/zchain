#!/usr/bin/env node
// =============================================================================
// scripts/verify_pack.mjs — 打包产物的 Chrome 真实加载验证（Extension 0.6）
//
// 用法：node scripts/verify_pack.mjs <unpacked 扩展目录>
//
// 做什么：用 Chrome for Testing（--headless=new + --load-extension）真实加载
// 打包目录，验证：
//   V1 扩展 service worker 成功启动（加载失败的扩展不会出现 SW target）；
//   V2 popup 页在真实扩展运行时内渲染（三个钱包模式按钮 + 渲染代数计数）；
//   V3 manifest 版本与 SW 提供的 provider 状态可达（runtime 消息往返）。
// 退出码：0 = PASS；1 = FAIL。
// =============================================================================

import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const EXT_DIR = path.resolve(process.argv[2] ?? path.join(HERE, '..', 'dist', 'unpacked'));

if (!existsSync(path.join(EXT_DIR, 'manifest.json'))) {
  console.error(`FAIL: ${EXT_DIR} 下没有 manifest.json（请先运行 pack.sh）`);
  process.exit(1);
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
  throw new Error('Chrome for Testing 未找到；请设置 ZCHAIN_CFT_CHROME 指向可执行文件');
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
  async eval(expr) {
    const r = await this.send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
    return r.result.value;
  }
}

async function main() {
  const manifest = JSON.parse(await import('node:fs').then((m) => m.promises.readFile(path.join(EXT_DIR, 'manifest.json'), 'utf8')));
  console.log(`verify target: ${EXT_DIR}`);
  console.log(`manifest: ${manifest.name} v${manifest.version}`);

  const chromeBin = findChrome();
  const profileDir = mkdtempSync(path.join(tmpdir(), 'zchain_pack_verify_'));
  const dbgPort = 11000 + Math.floor(Math.random() * 30000);
  const chrome = spawn(chromeBin, [
    '--headless=new',
    `--remote-debugging-port=${dbgPort}`,
    `--user-data-dir=${profileDir}`,
    '--no-first-run', '--no-default-browser-check',
    `--load-extension=${EXT_DIR}`,
    'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  let chromeErr = '';
  chrome.stderr.on('data', (d) => { chromeErr += d; });

  const cleanup = () => { try { chrome.kill('SIGKILL'); } catch { /* ignore */ } };
  process.on('exit', cleanup);
  process.on('SIGINT', () => { cleanup(); process.exit(130); });

  const devtools = `http://127.0.0.1:${dbgPort}`;
  let version = null;
  for (let i = 0; i < 100; i++) {
    try { version = await (await fetch(`${devtools}/json/version`)).json(); break; } catch { await sleep(300); }
  }
  if (!version) throw new Error(`DevTools 不可达:\n${chromeErr.slice(-1500)}`);
  console.log(`browser: ${version.Browser}`);

  // V1：扩展 service worker 出现 = 扩展被 Chrome 成功加载并运行
  let extId = null;
  for (let i = 0; i < 60; i++) {
    const targets = await (await fetch(`${devtools}/json/list`)).json();
    const sw = targets.find((t) => t.type === 'service_worker' && t.url.includes('/background/service_worker.js'));
    if (sw) { extId = new URL(sw.url).host; break; }
    await sleep(500);
  }
  if (!extId) throw new Error('service worker 未出现（扩展加载失败）');
  console.log(`V1 PASS: service worker 已启动（extension id ${extId}）`);
  await sleep(1500);

  // V2/V3：popup 页真实渲染 + runtime 消息可达
  const popupTarget = await (await fetch(`${devtools}/json/new?${encodeURIComponent(`chrome-extension://${extId}/popup/popup.html`)}`, { method: 'PUT' })).json();
  const conn = await Cdp.connect(popupTarget.webSocketDebuggerUrl);
  await conn.send('Runtime.enable');
  await conn.send('Page.enable');
  await sleep(1000);

  let g = null;
  for (let i = 0; i < 20 && g == null; i++) {
    g = await conn.eval('window.__zRenderGen ?? null').catch(() => null);
    if (g == null) await sleep(300);
  }
  if (g == null) throw new Error('popup 未完成渲染（__zRenderGen 未出现）');
  console.log(`V2 PASS: popup 渲染完成（render generation ${g}）`);

  const state = await conn.eval(`chrome.runtime.sendMessage({ type: 'popup:stkGetState' })`);
  if (!state || typeof state.hasWallet !== 'boolean' || !Array.isArray(state.networks)) {
    throw new Error(`runtime 消息往返异常: ${JSON.stringify(state)?.slice(0, 120)}`);
  }
  console.log(`V3 PASS: SW runtime 消息可达（stkGetState：${state.networks.length} 个 Starknet 网络预设）`);

  // 三模式按钮
  const buttons = await conn.eval(`(() => {
    const ids = ['mode-zchain', 'mode-evm', 'mode-stk'];
    return ids.map((id) => Boolean(document.getElementById(id)));
  })()`);
  if (!buttons.every(Boolean)) throw new Error(`模式按钮缺失: ${JSON.stringify(buttons)}`);
  console.log('V4 PASS: ZChain / EVM / Starknet 三个钱包模式按钮存在');

  console.log('\nVERIFY PASS：打包产物可在 Chrome 正常加载与运行');
  process.exit(0);
}

main().catch((e) => { console.error('VERIFY FAIL:', e?.message ?? e); process.exit(1); });
