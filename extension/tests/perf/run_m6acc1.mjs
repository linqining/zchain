#!/usr/bin/env node
// M6-ACC-1 浏览器验证吞吐 runner。
//
// 复用 E7 的驱动方式（Chrome for Testing + --headless=new + CDP
// WebSocket，见 extension/ACCEPTANCE.md 验证记录节）：本脚本
//   1. 定位 Chrome for Testing（env ZCHAIN_CFT_CHROME 或 /tmp/chrome/）
//   2. 起本地静态服务（serving extension/，wasm vendor 路径与扩展同源）
//   3. 打开 tests/perf/m6acc1.html?rounds=N，等待 window.__M6ACC1_DONE
//   4. 取回 window.__M6ACC1_RESULT → 写 tests/perf/m6acc1_result.json
//      + Page.captureScreenshot → tests/perf/m6acc1_screenshot.png
//
// 用法（repo 根目录）：
//   node extension/tests/perf/run_m6acc1.mjs            # 默认 50 轮 × 10 手
//   M6ACC1_ROUNDS=1 node extension/tests/perf/run_m6acc1.mjs   # 冒烟
// 退出码：0 = verdict PASS；1 = FAIL/ERROR。
// Node >= 21（内置 fetch 与 WebSocket；本机 Node v24.4.1 已验证）。

import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const EXT_ROOT = path.resolve(HERE, '..', '..'); // extension/
const OUT_JSON = path.join(HERE, 'm6acc1_result.json');
const OUT_PNG = path.join(HERE, 'm6acc1_screenshot.png');
const ROUNDS = process.env.M6ACC1_ROUNDS || '50';
const DONE_TIMEOUT_MS = 15 * 60 * 1000;

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json',
  '.wasm': 'application/wasm',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
};

function findChrome() {
  if (process.env.ZCHAIN_CFT_CHROME) return process.env.ZCHAIN_CFT_CHROME;
  const roots = ['/tmp/chrome', path.join(tmpdir(), 'chrome')];
  for (const root of roots) {
    if (!existsSync(root)) continue;
    for (const ver of readdirSync(root)) {
      for (const arch of ['chrome-mac-arm64', 'chrome-mac-x64']) {
        const cand = path.join(
          root, ver, arch,
          'Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
        );
        if (existsSync(cand)) return cand;
      }
    }
  }
  throw new Error('Chrome for Testing 未找到；请设置 ZCHAIN_CFT_CHROME 指向其可执行文件');
}

function serve(extRoot) {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      const urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname);
      let fsPath = path.normalize(path.join(extRoot, '.' + urlPath));
      if (!fsPath.startsWith(extRoot)) {
        res.writeHead(403).end('forbidden');
        return;
      }
      if (urlPath.endsWith('/')) fsPath = path.join(fsPath, 'index.html');
      try {
        const data = readFileSync(fsPath);
        res.writeHead(200, {
          'content-type': MIME[path.extname(fsPath).toLowerCase()] ?? 'application/octet-stream',
          'cache-control': 'no-store',
        });
        res.end(data);
      } catch {
        res.writeHead(404).end('not found');
      }
    });
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class CdpConn {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.console = [];
    ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
      } else if (msg.method === 'Runtime.consoleAPICalled') {
        this.console.push(msg.params.args.map((a) => a.value ?? a.description ?? '').join(' '));
      }
    });
  }
  static async connect(url) {
    const ws = new WebSocket(url);
    await new Promise((res, rej) => {
      ws.addEventListener('open', res, { once: true });
      ws.addEventListener('error', rej, { once: true });
    });
    return new CdpConn(ws);
  }
  send(method, params = {}) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
  }
  async eval(expr) {
    const r = await this.send('Runtime.evaluate', {
      expression: expr,
      awaitPromise: true,
      returnByValue: true,
    });
    if (r.exceptionDetails) {
      throw new Error(r.exceptionDetails.exception?.description ?? r.exceptionDetails.text);
    }
    return r.result.value;
  }
}

async function main() {
  const chromeBin = findChrome();
  const { server, port } = await serve(EXT_ROOT);
  const pageUrl = `http://127.0.0.1:${port}/tests/perf/m6acc1.html?rounds=${ROUNDS}`;
  const profileDir = mkdtempSync(path.join(tmpdir(), 'zchain_m6acc1_'));
  const dbgPort = 10000 + Math.floor(Math.random() * 40000);

  console.log(`chrome: ${chromeBin}`);
  console.log(`page:   ${pageUrl}`);
  const chrome = spawn(
    chromeBin,
    [
      '--headless=new',
      `--remote-debugging-port=${dbgPort}`,
      `--user-data-dir=${profileDir}`,
      '--no-first-run',
      '--no-default-browser-check',
      '--enable-precise-memory-info',
      // 泄漏判据需要"GC 后留存堆"：暴露 gc() 供页面每轮采样前强制回收
      // （无此开关时 usedJSHeapSize 含未回收垃圾，趋势只反映分配churn）。
      '--js-flags=--expose-gc',
      'about:blank',
    ],
    { stdio: ['ignore', 'ignore', 'pipe'] },
  );
  let chromeErr = '';
  chrome.stderr.on('data', (d) => { chromeErr += d; });

  const cleanup = () => {
    try { chrome.kill('SIGKILL'); } catch { /* ignore */ }
    server.close();
  };
  process.on('exit', cleanup);
  process.on('SIGINT', () => { cleanup(); process.exit(130); });

  try {
    // 等 DevTools 端口就绪
    const devtools = `http://127.0.0.1:${dbgPort}`;
    let version = null;
    for (let i = 0; i < 100; i++) {
      try {
        version = await (await fetch(`${devtools}/json/version`)).json();
        break;
      } catch { await sleep(300); }
    }
    if (!version) throw new Error(`DevTools endpoint not reachable:\n${chromeErr.slice(-2000)}`);
    console.log(`target: ${version.Browser}`);

    // 打开 perf 页面（Chrome 111+ 需要 PUT /json/new）
    const target = await (await fetch(`${devtools}/json/new?${encodeURIComponent(pageUrl)}`, { method: 'PUT' })).json();
    const conn = await CdpConn.connect(target.webSocketDebuggerUrl);
    await conn.send('Runtime.enable');
    await conn.send('Page.enable');

    // 逐轮收集：页面每轮 post-GC 采样后把明细挂到 __M6ACC1_ROUND 并置
    // ROUND_READY；runner 取走并 ACK。页面因此不必 retain 每轮明细，
    // "GC 后留存堆"度量的是验证工作负载本身（非 harness 报告累积）。
    const collectedRounds = [];
    const t0 = Date.now();
    let roundsExpected = null;
    for (;;) {
      if (Date.now() - t0 > DONE_TIMEOUT_MS) throw new Error('timeout waiting for __M6ACC1_DONE');
      await sleep(100);
      const state = await conn.eval(
        `({ ready: window.__M6ACC1_ROUND_READY === true, done: window.__M6ACC1_DONE === true, rounds: ${roundsExpected ?? 'null'} })`,
      );
      if (state.ready) {
        const detail = await conn.eval('JSON.stringify(window.__M6ACC1_ROUND)');
        collectedRounds.push(JSON.parse(detail));
        roundsExpected = collectedRounds.length + 1;
        await conn.eval('window.__M6ACC1_ROUND_ACK = true; window.__M6ACC1_ROUND_READY = false;');
      }
      if (state.done) break;
    }
    await sleep(200);
    const parsed = JSON.parse(await conn.eval('JSON.stringify(window.__M6ACC1_RESULT)'));
    // 合并：cdp-collect 模式页面只有摘要，明细以 runner 收集为准；
    // standalone 模式页面自留明细，直接采用。
    if (parsed.meta.collection_mode === 'cdp-collect' && collectedRounds.length === parsed.meta.rounds) {
      parsed.rounds = collectedRounds;
    } else if (parsed.meta.collection_mode === 'standalone-self-retain') {
      console.log('note: standalone-self-retain mode (runner collect failed) — heap criteria include report retention');
    }
    writeFileSync(OUT_JSON, JSON.stringify(parsed, null, 2) + '\n');
    console.log(`result: ${OUT_JSON}`);

    const shot = await conn.send('Page.captureScreenshot', { format: 'png' });
    writeFileSync(OUT_PNG, Buffer.from(shot.data, 'base64'));
    console.log(`shot:   ${OUT_PNG}`);

    const logs = conn.console.filter((l) => l.includes('M6ACC1'));
    console.log(`console: ${logs.length} M6ACC1 line(s)`);
    console.log(`verdict: ${parsed.verdict}`);
    if (parsed.stats) {
      console.log(`  correct: ${parsed.stats.correct}/${parsed.stats.hands_total}`);
      console.log(`  median/p95/max per-hand: ${parsed.stats.median_ms}/${parsed.stats.p95_ms}/${parsed.stats.max_ms} ms`);
    }
    if (parsed.heap) {
      console.log(`  heap growth: ${parsed.heap.growth_pct}% (first3 ${parsed.heap.first3_avg_bytes}B -> last3 ${parsed.heap.last3_avg_bytes}B), tail10 max run +${parsed.heap.tail10_max_consecutive_increase}, pass=${parsed.heap.pass}`);
    }
    if (parsed.wasm_linear_memory) {
      console.log(`  wasm mem growth: ${parsed.wasm_linear_memory.growth_pct}% (first3 ${parsed.wasm_linear_memory.first3_avg_bytes}B -> last3 ${parsed.wasm_linear_memory.last3_avg_bytes}B), pass=${parsed.wasm_linear_memory.pass}`);
    }
    process.exit(parsed.verdict === 'PASS' ? 0 : 1);
  } finally {
    cleanup();
  }
}

main().catch((e) => {
  console.error('runner error:', e);
  process.exit(1);
});
