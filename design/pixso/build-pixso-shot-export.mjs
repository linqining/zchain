#!/usr/bin/env node
/* =============================================================================
 * design/pixso/build-pixso-shot-export.mjs — 「账簿 Ledger」设计稿导出(运行时版)
 *
 * 为什么不用 build-pixso-import.js:后者静态枚举 <template id="t-*">,而方向 B 的
 * t-acct 是一份模板实例化三次(zc / evm / stk 三个数据面)。静态抽取会塌缩成 1 块板,
 * 且跳过 applyChain —— 导出的 06-acct 里三链面板同时可见,是坏板。
 *
 * 本脚本用 Chrome --dump-dom 驱动原型自带 shot 模式(#shot=1&s=<id>&g=<ground>),
 * 让页面自己的 boot() + applyChain() 渲染完,再从渲染结果里取 #shot-mount,连同同源
 * CSS、图标 sprite 写成固定 380×600 画板的独立 HTML,供 Pixso code_to_design 逐屏导入。
 * 走 file:// + CLI,不需要 CDP/WebSocket,也不占用本地端口。
 *
 * 产出:
 *   <out>.screens/NN-<id>.html         逐屏 380×600 画板(popup 首屏,导入 Pixso 用)
 *   <out>.screens/NN-<id>__full.html   同屏整屏版(按内容撑高,评审完整内容用)
 *   <out>.screens/ds/NN-<ds-n>.html    设计系统板(1240 宽自适应高度)
 *   <out>                              整板(自助导入:整板复制粘贴)
 *
 * 用法:node design/pixso/build-pixso-shot-export.mjs
 *   --src=<file.html>        源原型(默认 ../zchain-wallet-ui-b-ledger.html)
 *   --out=<file.html>        整板输出(默认 ./pixso-b-ledger.html)
 *   --title=<str>            整板标题
 *   --ground=paper|night     底色(默认 paper)
 *   --only=id1,id2           只导这些屏(调试)
 *   --no-aggregate           跳过整板生成
 *   --no-full                跳过整屏版(省一半 Chrome 启动,少一份裁切体检报告)
 *
 * Chrome for Testing 定位同 design/figma/build.mjs(ZCHAIN_CFT_CHROME 可覆盖)。
 * ============================================================================= */
"use strict";

import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve, basename } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

/* ---------- 参数 ---------- */
const arg = (name, dflt) => {
  const hit = process.argv.slice(2).find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : dflt;
};
const flag = (name) => process.argv.slice(2).includes(`--${name}`);

const SRC = resolve(HERE, arg("src", "../zchain-wallet-ui-b-ledger.html"));
const OUT = resolve(HERE, arg("out", "./pixso-b-ledger.html"));
const TITLE = arg("title", "ZChain Wallet · 方向 B 账簿 Ledger (Paper)");
const GROUND = arg("ground", "paper");
const ONLY = arg("only", "").split(",").map((s) => s.trim()).filter(Boolean);
const SCREENS_DIR = join(dirname(OUT), basename(OUT, ".html") + ".screens");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

if (!["paper", "night"].includes(GROUND)) {
  console.error(`--ground 只接受 paper|night,收到:${GROUND}`);
  process.exit(1);
}
if (!existsSync(SRC)) { console.error(`源原型不存在:${SRC}`); process.exit(1); }

/* ---------- 1. 解析原型:CSS / 图标 sprite / 屏幕注册表 ---------- */
const srcHtml = readFileSync(SRC, "utf8");

const cssBlocks = [...srcHtml.matchAll(/<style>([\s\S]*?)<\/style>/g)].map((m) => m[1]);
if (!cssBlocks.length) throw new Error("原型里没有 <style> 块");
const CSS = cssBlocks.join("\n");

const spriteStart = srcHtml.indexOf('<svg width="0"');
let sprite = "";
if (spriteStart >= 0) {
  const spriteEnd = srcHtml.indexOf("</svg>", spriteStart) + "</svg>".length;
  sprite = srcHtml.slice(spriteStart, spriteEnd);
} else {
  console.warn("warn: 没找到图标 sprite(<svg width=\"0\"),SVG 图标可能缺失");
}

const regStart = srcHtml.indexOf("const SCREENS=[");
if (regStart < 0) throw new Error("找不到 const SCREENS=[ 注册表");
const regBody = srcHtml.slice(regStart, srcHtml.indexOf("\n];", regStart));
const SCREENS = [...regBody.matchAll(/\{\s*id:'([a-z0-9-]+)'[\s\S]*?name:'([^']*)'[\s\S]*?\}/g)].map((m) => {
  const entry = m[0];
  const seg = /seg:'([a-z]+)'/.exec(entry);
  const tpl = /tpl:'([^']+)'/.exec(entry);
  return { id: m[1], name: m[2], seg: seg ? seg[1] : null, tpl: tpl ? tpl[1] : m[1] };
});
if (!SCREENS.length) throw new Error("SCREENS 注册表解析为空");
const wanted = ONLY.length ? SCREENS.filter((s) => ONLY.includes(s.id)) : SCREENS;
if (!wanted.length) { console.error(`--only 里没有一个屏存在于注册表;可选:${SCREENS.map(s=>s.id).join(",")}`); process.exit(1); }

const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/* ---------- 2. Chrome for Testing(仅用 CLI:--dump-dom) ---------- */
function findChrome() {
  if (process.env.ZCHAIN_CFT_CHROME) return process.env.ZCHAIN_CFT_CHROME;
  for (const root of ["/tmp/chrome", join(tmpdir(), "chrome")]) {
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
const CHROME = findChrome();

/** 让页面按 shot 模式渲染完,返回渲染后的 DOM 字符串 */
function dumpShot(hashQuery, tag) {
  const url = `file://${SRC}#${hashQuery}`;
  // 参数固定为已验证的最小集:再加 --user-data-dir 新 profile 会走首次启动流程,
  // --dump-dom 直接不输出(macOS / Chrome 153 实测)。全程串行,不并发。
  const args = [
    "--headless=new", "--disable-gpu", "--no-sandbox",
    "--window-size=1440,1000",
    "--virtual-time-budget=5000", // 让字体 / rAF 测高跑完
    "--dump-dom", url,
  ];
  return new Promise((ok, bad) => {
    const child = spawn(CHROME, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (err += d));
    child.on("error", bad);
    child.on("exit", (code) => {
      if (!out.includes("<")) { bad(new Error(`${tag}: chrome 无 DOM 输出 (exit ${code}) ${err.slice(0, 200)}`)); return; }
      ok(out);
    });
    setTimeout(() => { child.kill("SIGKILL"); bad(new Error(`${tag}: chrome 超时(>60s)已杀掉`)); }, 60000);
  });
}

/** 从渲染结果里取 #shot-mount 的 innerHTML 与其属性(class / style) */
function takeMount(dom, tag) {
  const open = dom.search(/<div[^>]*id="shot-mount"/);
  if (open < 0) throw new Error(`${tag}: 渲染结果里没有 #shot-mount`);
  const openTag = /<div[^>]*>/.exec(dom.slice(open))[0];
  const clsM = /class="([^"]*)"/.exec(openTag);
  const styleM = /style="([^"]*)"/.exec(openTag);
  let i = open + openTag.length, depth = 1;
  const scan = /<div\b|<\/div>/g;
  scan.lastIndex = i;
  let m, end = -1;
  while ((m = scan.exec(dom))) {
    if (m[0] === "</div>") { if (--depth === 0) { end = m.index; break; } }
    else depth++;
  }
  if (end < 0) throw new Error(`${tag}: #shot-mount 的 div 未闭合`);
  const inner = dom.slice(i, end).trim();
  if (!/<div/.test(inner)) throw new Error(`${tag}: #shot-mount 是空的(screen id 或 DS 标号不对)`);
  return { frag: inner, cls: clsM ? clsM[1] : "", style: styleM ? styleM[1] : "" };
}

const MOUNT_ATTRS = (cls, style) => {
  const parts = [];
  if (cls) parts.push(`class="${cls}"`);
  if (style) parts.push(`style="${style}"`);
  return parts.length ? " " + parts.join(" ") : "";
};

/** size=fixed 锁 380×600(popup 首屏);size=auto 按内容撑高(整屏评审用) */
const standalone = (label, frag, cls, style, size) => {
  const fixed = size !== "auto";
  return `<!DOCTYPE html>
<html lang="zh-CN" data-ground="${GROUND}">
<head>
<meta charset="UTF-8">
<title>${esc(label)}</title>
<style>
${CSS}
/* ====== 导出画板:单屏静态可见,供 Pixso code_to_design 导入 ====== */
html,body{margin:0;padding:0;${fixed ? "width:380px;height:600px;overflow:hidden;" : "width:380px;"}background:var(--pg)}
.shell-bar,#proto-wrap,#gallery,template{display:none !important}
#shot-mount{box-shadow:none;margin:0 !important}
</style>
</head>
<body class="mode-shot">${sprite}
<div id="shot-mount"${MOUNT_ATTRS(cls, style)}>${frag}</div>
</body>
</html>
`;
};

/* ---------- 3. 逐屏导出 ---------- */
mkdirSync(SCREENS_DIR, { recursive: true });
for (const stale of readdirSync(SCREENS_DIR)) {
  if (/^\d{2}-.+\.html$/.test(stale) || stale === "ds") rmSync(join(SCREENS_DIR, stale), { recursive: true, force: true });
}

const board = [];
const report = [];
let seq = 0;
for (let i = 0; i < wanted.length; i++) {
  const s = wanted[i];
  const nn = String(i + 1).padStart(2, "0");
  const dom = await dumpShot(`shot=1&s=${s.id}&g=${GROUND}`, s.id);
  const { frag, cls } = takeMount(dom, s.id);
  const label = `${nn} · ${s.name}` + (s.seg ? ` [${s.seg}]` : "");
  writeFileSync(join(SCREENS_DIR, `${nn}-${s.id}.html`), standalone(label, frag, cls));
  board.push({ no: nn, id: s.id, name: s.name, seg: s.seg, frag });

  let clipped = 0;
  if (!flag("no-full")) {
    const fdom = await dumpShot(`shot=1&s=${s.id}&g=${GROUND}&full=1`, `${s.id} full`);
    const f = takeMount(fdom, `${s.id} full`);
    writeFileSync(join(SCREENS_DIR, `${nn}-${s.id}__full.html`), standalone(`${label} · 整屏`, f.frag, f.cls, f.style, "auto"));
    const h = /height:\s*(\d+)/.exec(f.style || "");
    if (h) clipped = Math.max(0, Number(h[1]) - 600);
  }
  report.push({ screen: `${nn}-${s.id}`, seg: s.seg || "-", clipped });
  console.log(`[${String(++seq).padStart(2, "0")}] ${label}${clipped ? `  · 内容超出画板 ${clipped}px` : ""}`);
}

/* ---------- 4. 设计系统板(标号从原型里读,DS-n 与 shot 模式的 &ds= 对应) ---------- */
const labels = [...srcHtml.matchAll(/class="no"[^>]*>\s*(DS-\d+)\s*</g)].map((m) => m[1]);
const DS_LABELS = [...new Set(labels)];
if (!DS_LABELS.length) console.warn("warn: 原型里没找到 DS-n 标号,跳过设计系统板");
mkdirSync(join(SCREENS_DIR, "ds"), { recursive: true });
const dsBoards = [];
for (let i = 0; i < DS_LABELS.length; i++) {
  const label = DS_LABELS[i];
  const n = label.replace("DS-", "");
  let dom;
  try { dom = await dumpShot(`shot=1&ds=${n}&g=${GROUND}`, label); }
  catch (e) { console.warn(`skip ${label}: ${e.message}`); continue; }
  const { frag, cls, style } = takeMount(dom, label);
  const nn = String(i + 1).padStart(2, "0");
  writeFileSync(join(SCREENS_DIR, "ds", `${nn}-${label.toLowerCase()}.html`), standalone(`${label} · 设计系统`, frag, cls || "doc", style, "auto"));
  dsBoards.push({ no: label, frag });
  console.log(`[${String(++seq).padStart(2, "0")}] ${label} · 设计系统板`);
}

/* ---------- 5. 整板(自助导入用) ---------- */
if (!flag("no-aggregate")) {
  const cells = board.map((b) => `
    <div class="px-cell">
      <div class="frame"><div class="frame-in">${b.frag}</div></div>
      <div class="px-cap"><span class="px-no">${b.no}</span><b>${esc(b.name)}</b><small>${esc(b.id)}${b.seg ? " · " + b.seg : ""}</small></div>
    </div>`).join("");
  const ds = dsBoards.map((d) => `  <div class="px-ds">${d.frag}</div>`).join("\n");
  writeFileSync(OUT, `<!DOCTYPE html>
<html lang="zh-CN" data-ground="${GROUND}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(TITLE)}</title>
<style>
${CSS}

/* ====== Pixso import layout(chrome stripped; every screen visible) ====== */
body{background:var(--pg)}
.shell-bar,#proto-wrap,#gallery,template{display:none !important}
.px-canvas{max-width:1660px;margin:0 auto;padding:36px 32px 96px}
.px-head{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap;margin:0 0 8px}
.px-head h1{font-size:22px;letter-spacing:.01em}
.px-head .px-sub{color:var(--dim);font-family:var(--font-mono);font-size:12px}
.px-note{color:var(--muted);font-size:12.5px;max-width:900px;margin:0 0 26px;line-height:1.7}
.px-sec{font-size:13px;color:var(--dim);font-family:var(--font-mono);letter-spacing:.14em;text-transform:uppercase;margin:44px 0 18px;padding-top:18px;border-top:1px solid var(--border-soft,var(--rl))}
.px-frames{display:flex;flex-wrap:wrap;gap:34px 30px;align-items:flex-start}
.px-cell{display:flex;flex-direction:column;gap:10px;width:384px}
.px-cell .frame{width:380px;height:600px;padding:0;border:none;border-radius:0;background:var(--pg);box-shadow:0 0 0 1px var(--rl-2)}
.px-cell .frame-in{position:relative;overflow:hidden;border-radius:0}
.px-cell .frame-in .scr{position:absolute;inset:0;display:flex}
.px-cap{display:flex;align-items:baseline;gap:8px;padding:0 2px}
.px-cap .px-no{font-family:var(--font-mono);font-size:10.5px;color:var(--dim)}
.px-cap b{font-size:13px}
.px-cap small{margin-left:auto;font-family:var(--mono);font-size:10.5px;color:var(--dim)}
.px-ds{margin:0 0 40px}
.px-ds .ds-sec{margin-bottom:0}
</style>
</head>
<body>
${sprite}
<div class="px-canvas">
  <div class="px-head"><h1>${esc(TITLE)}</h1><span class="px-sub">380×600 · ${board.length} 屏 + ${dsBoards.length} 设计系统板 · 供 Pixso 导入</span></div>
  <p class="px-note">由 design/pixso/build-pixso-shot-export.mjs 驱动原型 shot 模式导出:每块画板都是页面运行时渲染结果(t-acct 已按链跑过 applyChain,三链各一块板),已剥离总览/交互外壳。品牌 token 同源 website/media-kit/v0.1。</p>
  <div class="px-sec">Screens · ${board.length}</div>
  <div class="px-frames">${cells}
  </div>
  <div class="px-sec">Design System</div>
${ds}
</div>
</body>
</html>`);
  console.log(`整板 -> ${OUT}`);
}

/* ---------- 6. 收尾与体检报告 ---------- */
console.log(`\nOK ${wanted.length} 屏 + ${dsBoards.length} 设计系统板 -> ${SCREENS_DIR}/`);
if (!flag("no-full")) {
  const clipped = report.filter((r) => r.clipped > 1);
  console.log(clipped.length
    ? `内容超出 380×600 的屏(画板按 popup 首屏裁切,需要时可单独出整屏版):\n` +
      clipped.map((r) => `  ${r.screen} 超出 ${r.clipped}px`).join("\n")
    : "所有屏内容均在 380×600 画板内,无裁切。");
}
const multi = board.filter((b) => b.seg);
if (multi.length) console.log(`账簿三实例:${multi.map((b) => `${b.no}-${b.id}(${b.seg})`).join(" / ")}`);
