#!/usr/bin/env node
/* =============================================================================
 * design/figma/build.mjs — 「账簿 Ledger」移动版出图管线
 *
 * 从 wallet-app/mobile/www(设计稿 19 屏的手机尺寸移植)批量产出:
 *   png/<NN>-<id>__<ground>.png      整屏(内容撑满高度)@3x — 393 逻辑宽
 *   png/<NN>-<id>__<ground>_vp.png   手机视口 393×852 @3x(可见区域)
 *   screens/<NN>-<id>__<ground>.html 独立单屏 HTML(CSS/图标内联,固定画板)
 *   tokens.json                      Tokens Studio 兼容设计令牌(双底色)
 *
 * 零依赖(node 内置 http + WebSocket)。Chrome for Testing 定位逻辑与
 * extension/tests/e2e/run_09.mjs 一致(ZCHAIN_CFT_CHROME 可覆盖)。
 *
 * 用法:node design/figma/build.mjs
 * ============================================================================= */
"use strict";

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { createServer } from "node:http";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));
const WWW = resolve(HERE, "../../wallet-app/mobile/www");
const OUT = HERE;
const W = 393, H = 852, DPR = 3; // iPhone 14/15 Pro 逻辑尺寸
const GROUNDS = ["paper", "night"];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ---------- 屏幕清单(与 www/js/app.js 的 SCREENS 同序) ---------- */
const SCREENS = [
  "welcome", "success", "import", "lock", "home",
  "zc-dash", "evm-dash", "stk-dash",
  "zc-send", "zc-withdraw", "zc-confirm", "zc-sessions", "zc-portal", "zc-receipts",
  "evm-send", "evm-history", "evm-manage",
  "proofs", "settings",
];

/* ---------- 1. 静态服务 ---------- */
const MIME = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml" };
function serve(root) {
  return new Promise((ok, bad) => {
    const srv = createServer((req, res) => {
      const p = join(root, req.url === "/" ? "index.html" : req.url.split("?")[0]);
      if (!p.startsWith(root) || !existsSync(p)) { res.writeHead(404); res.end("nf"); return; }
      res.writeHead(200, { "Content-Type": MIME[p.slice(p.lastIndexOf("."))] || "application/octet-stream" });
      res.end(readFileSync(p));
    });
    srv.on("error", bad);
    srv.listen(0, "127.0.0.1", () => ok({ srv, port: srv.address().port }));
  });
}

/* ---------- 2. Chrome for Testing ---------- */
function findChrome() {
  if (process.env.ZCHAIN_CFT_CHROME) return process.env.ZCHAIN_CFT_CHROME;
  const roots = ["/tmp/chrome", join(tmpdir(), "chrome")];
  for (const root of roots) {
    if (!existsSync(root)) continue;
    for (const ver of readdirSync(root)) {
      for (const arch of ["chrome-mac-arm64", "chrome-mac-x64"]) {
        const cand = join(root, ver, arch, "Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing");
        if (existsSync(cand)) return cand;
      }
    }
  }
  throw new Error("Chrome for Testing 未找到;请设置 ZCHAIN_CFT_CHROME");
}

async function cdpClient(wsUrl) {
  const ws = new WebSocket(wsUrl);
  await new Promise((ok, bad) => { ws.onopen = ok; ws.onerror = () => bad(new Error("ws fail")); });
  let id = 0;
  const pending = new Map();
  const events = [];
  ws.addEventListener("message", (ev) => {
    const m = JSON.parse(ev.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
    else if (m.method) events.push(m);
  });
  const send = (method, params = {}) => new Promise((ok, bad) => {
    const mid = ++id;
    pending.set(mid, (m) => (m.error ? bad(new Error(method + ": " + JSON.stringify(m.error))) : ok(m.result)));
    ws.send(JSON.stringify({ id: mid, method, params })); // CDP 不用 jsonrpc 字段
  });
  const waitEvent = (method, timeout = 15000) => new Promise((ok, bad) => {
    const t0 = Date.now();
    (function poll() {
      const i = events.findIndex((e) => e.method === method);
      if (i >= 0) { ok(events.splice(i, 1)[0]); return; }
      if (Date.now() - t0 > timeout) { bad(new Error("event timeout: " + method)); return; }
      setTimeout(poll, 25);
    })();
  });
  return { send, waitEvent, close: () => ws.close() };
}

/* ---------- 3. 主流程 ---------- */
setTimeout(() => { console.error("GLOBAL WATCHDOG TIMEOUT"); process.exit(2); }, 300000).unref();
const log = (...a) => console.log(new Date().toISOString().slice(11, 23), ...a);
const { srv, port: PORT } = await serve(WWW);
log("static server on 127.0.0.1:" + PORT);
const chromeBin = findChrome();
const profile = mkdtempSync(join(tmpdir(), "zc_figma_"));
log("chrome:", chromeBin);
const chrome = spawn(chromeBin, [
  "--headless=new", "--remote-debugging-port=0", `--user-data-dir=${profile}`,
  "--no-first-run", "--no-default-browser-check", "--disable-gpu", "about:blank",
], { stdio: ["ignore", "ignore", "pipe"] });
const dbg = await new Promise((ok, bad) => {
  let acc = "";
  chrome.stderr.on("data", (d) => {
    acc += d.toString();
    const m = acc.match(/DevTools listening on ws:\/\/127\.0\.0\.1:(\d+)\S*/);
    if (m) ok(m[1]);
  });
  chrome.on("exit", () => bad(new Error("chrome exited early: " + acc)));
  setTimeout(() => bad(new Error("devtools port timeout")), 20000);
});
log("devtools port:", dbg);
let list = [];
for (let tries = 0; tries < 20; tries++) {
  list = await (await fetch(`http://127.0.0.1:${dbg}/json/list`)).json().catch(() => []);
  if (list.find((t) => t.type === "page")) break;
  await sleep(250);
}
const page = list.find((t) => t.type === "page");
if (!page) throw new Error("no page target after retries");
log("cdp ws open");
const cdp = await cdpClient(page.webSocketDebuggerUrl);

await cdp.send("Page.enable");
log("Page.enable ok");
mkdirSync(join(OUT, "png"), { recursive: true });
mkdirSync(join(OUT, "screens"), { recursive: true });

let n = 0;
for (let i = 0; i < SCREENS.length; i++) {
  const id = SCREENS[i];
  const nn = String(i + 1).padStart(2, "0");
  for (const g of GROUNDS) {
    n++;
    // 先把视口复位到手机尺寸,再开新文档,避免上一屏的 metrics 残留影响 dvh 布局
    await cdp.send("Emulation.setDeviceMetricsOverride", { width: W, height: H, deviceScaleFactor: DPR, mobile: true });
    await cdp.send("Page.navigate", { url: "about:blank" }); // 强制新文档,否则纯 hash 导航不触发 loadEventFired
    await cdp.waitEvent("Page.loadEventFired");
    const url = `http://127.0.0.1:${PORT}/index.html#shot=${id}&g=${g}&full=1`;
    await cdp.send("Page.navigate", { url });
    await cdp.waitEvent("Page.loadEventFired");
    await sleep(400); // rAF 测高 + 字体稳定
    // CSS 内联后导出独立单屏 HTML(Pixso code_to_design / html.to.design 的输入)
    const { result } = await cdp.send("Runtime.evaluate", {
      expression: `fetch('css/app.css').then(r=>r.text()).then(css=>{const s=document.createElement('style');s.textContent=css;document.head.appendChild(s)}).then(()=>window.__exportStandalone())`,
      awaitPromise: true, returnByValue: true,
    });
    if (result?.value) writeFileSync(join(OUT, "screens", `${nn}-${id}__${g}.html`), result.value);
    const hRes = await cdp.send("Runtime.evaluate", {
      expression: "Number(document.querySelector('.scr')?.dataset.fullH) || document.documentElement.scrollHeight",
      returnByValue: true,
    });
    const fullH = Math.min(Number(hRes.result?.value) || H, 6000);
    // 整屏 PNG @3x(把视口撑到内容高度后整页截取)
    await cdp.send("Emulation.setDeviceMetricsOverride", { width: W, height: fullH, deviceScaleFactor: DPR, mobile: true });
    await sleep(150);
    const shot = await cdp.send("Page.captureScreenshot", { format: "png" });
    writeFileSync(join(OUT, "png", `${nn}-${id}__${g}.png`), Buffer.from(shot.data, "base64"));
    // 视口 PNG(手机首屏可见区)
    const vshot = await cdp.send("Page.captureScreenshot", { format: "png", clip: { x: 0, y: 0, width: W, height: H, scale: 1 } });
    writeFileSync(join(OUT, "png", `${nn}-${id}__${g}_vp.png`), Buffer.from(vshot.data, "base64"));
    log(`[${String(n).padStart(2, "0")}/38] ${id} · ${g} · full ${fullH}px`);
  }
}

chrome.kill();
srv.close();
rmSync(profile, { recursive: true, force: true });
log("DONE →", OUT);
