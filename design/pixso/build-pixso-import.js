#!/usr/bin/env node
/*
 * build-pixso-import.js
 * Transform the two ZChain Wallet design mockups into clean, Pixso-importable
 * "board" HTML: every one of the 18 popup screens rendered as a standalone
 * 380x600 device frame on a grid, plus the design-system boards. The gallery /
 * proto toolbar chrome and the JS that toggles screen visibility are stripped so
 * that a static HTML->design converter (Pixso code_to_design) sees every screen.
 *
 * Usage: node build-pixso-import.js <src.html> <out.html> <title> [dataGround]
 */
const fs = require('fs');

const [, , src, out, title, dataGround] = process.argv;
if (!src || !out) {
  console.error('args: <src.html> <out.html> <title> [dataGround]');
  process.exit(1);
}
const html = fs.readFileSync(src, 'utf8');

function between(str, openMark, closeMark, from = 0) {
  const a = str.indexOf(openMark, from);
  if (a < 0) return null;
  const b = str.indexOf(closeMark, a + openMark.length);
  if (b < 0) return null;
  return { pre: str.slice(0, a), open: str.slice(a, a + openMark.length), body: str.slice(a + openMark.length, b), close: str.slice(b, b + closeMark.length), end: b + closeMark.length };
}

// <style> ... </style>
const style = between(html, '<style>', '</style>');
if (!style) throw new Error('no <style>');
const styleCss = style.body;

// icon sprite: <svg width="0" ...> ... </svg>
const spriteStart = html.indexOf('<svg width="0"');
let sprite = '';
if (spriteStart >= 0) {
  const spriteEnd = html.indexOf('</svg>', spriteStart) + '</svg>'.length;
  sprite = html.slice(spriteStart, spriteEnd);
}

// balanced extractor for a given tag name, returns array of full blocks
function extractBalanced(str, tag, attrsRe) {
  const openRe = new RegExp('<' + tag + '\\b([^>]*)>', 'g');
  const closeTok = '</' + tag + '>';
  const blocks = [];
  let m;
  while ((m = openRe.exec(str))) {
    const attrs = m[1];
    if (attrsRe && !attrsRe.test(attrs)) continue;
    // walk to matching close
    let depth = 1;
    let i = openRe.lastIndex;
    const scan = new RegExp('<' + tag + '\\b[^>]*>|</' + tag + '>', 'g');
    scan.lastIndex = i;
    let s, endIdx = -1;
    while ((s = scan.exec(str))) {
      if (s[0][1] === '/') depth--;
      else if (!/\/>$/.test(s[0])) depth++;
      if (depth === 0) { endIdx = s.index + s[0].length; break; }
    }
    if (endIdx < 0) continue;
    blocks.push({ full: str.slice(m.index, endIdx), attrs });
    openRe.lastIndex = endIdx;
  }
  return blocks;
}

// design-system sections (drop the JS-populated shot-grid placeholder)
const dsSections = extractBalanced(html, 'section', /class="[^"]*\bds-(section|sec)\b/)
  .map(b => b.full)
  .filter(s => !/id="shot-grid"/.test(s));

// screens from <template id="t-NAME"> ... </template>
const tplRe = /<template\s+id="t-([a-z0-9-]+)">([\s\S]*?)<\/template>/g;
const screens = [];
let t;
while ((t = tplRe.exec(html))) {
  const id = t[1];
  const inner = t[2].trim();
  const labelM = /aria-label="([^"]*)"/.exec(inner);
  const label = labelM ? labelM[1] : id;
  screens.push({ id, label, inner });
}

const htmlEsc = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

const cells = screens.map((s, i) => `
    <div class="px-cell">
      <div class="frame"><div class="frame-inner">${s.inner}</div></div>
      <div class="px-cap"><span class="px-no">${String(i + 1).padStart(2, '0')}</span><b>${htmlEsc(s.label)}</b><small>${s.id}</small></div>
    </div>`).join('');

const dsBoards = dsSections.map(s => `  <div class="px-ds">${s}</div>`).join('\n');

const groundAttr = dataGround ? ` data-ground="${dataGround}"` : '';

const doc = `<!DOCTYPE html>
<html lang="zh-CN"${groundAttr}>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${htmlEsc(title)}</title>
<style>
${styleCss}

/* ====== Pixso import layout (chrome stripped; every screen visible) ====== */
body{background:${dataGround === 'night' ? 'var(--pg)' : (dataGround ? 'var(--pg)' : '#040806')}}
.shell-bar,#proto-wrap,.mode-gallery #proto-wrap{display:none !important}
.px-canvas{max-width:1660px;margin:0 auto;padding:36px 32px 96px}
.px-head{display:flex;align-items:baseline;gap:14px;flex-wrap:wrap;margin:0 0 8px}
.px-head h1{font-size:22px;letter-spacing:.01em}
.px-head .px-sub{color:var(--dim);font-family:var(--font-mono);font-size:12px}
.px-note{color:var(--muted);font-size:12.5px;max-width:900px;margin:0 0 26px;line-height:1.7}
.px-sec{font-size:13px;color:var(--dim);font-family:var(--font-mono);letter-spacing:.14em;text-transform:uppercase;margin:44px 0 18px;padding-top:18px;border-top:1px solid var(--border-soft,var(--rl))}
.px-frames{display:flex;flex-wrap:wrap;gap:34px 30px;align-items:flex-start}
.px-cell{display:flex;flex-direction:column;gap:10px;width:384px}
.px-cell .frame{width:380px;height:600px}
.px-cell .frame-inner .screen,.px-cell .frame-inner .scr{position:absolute;inset:0;display:flex}
.px-cap{display:flex;align-items:baseline;gap:8px;padding:0 2px}
.px-cap .px-no{font-family:var(--font-mono);font-size:10.5px;color:var(--dim)}
.px-cap b{font-size:13px}
.px-cap small{margin-left:auto;font-family:var(--font-mono);font-size:10.5px;color:var(--dim)}
.px-ds{margin:0 0 40px}
.px-ds .ds-section,.px-ds .ds-sec{margin-bottom:0}
</style>
</head>
<body>
${sprite}
<div class="px-canvas">
  <div class="px-head"><h1>${htmlEsc(title)}</h1><span class="px-sub">380×600 · ${screens.length} 屏 + 设计系统 · 供 Pixso 导入</span></div>
  <p class="px-note">本文件由 design/pixso/build-pixso-import.js 从设计稿自动抽取生成：已剥离总览/交互外壳与切换脚本，使每一屏都以固定画板形式静态可见，便于 Pixso <span class="mono">code_to_design</span> 逐屏或整板导入。品牌 token 同源 website/media-kit/v0.1。</p>
  <div class="px-sec">Screens · ${screens.length}</div>
  <div class="px-frames">${cells}
  </div>
  <div class="px-sec">Design System</div>
${dsBoards}
</div>
</body>
</html>`;

fs.writeFileSync(out, doc);
console.log(`OK ${out}: ${screens.length} screens, ${dsSections.length} DS boards`);

// ---- per-screen standalone 380x600 files (clean Pixso code_to_design frames) ----
const path = require('path');
const dir = path.join(path.dirname(out), path.basename(out, '.html') + '.screens');
fs.mkdirSync(dir, { recursive: true });
const perGround = dataGround ? ` data-ground="${dataGround}"` : '';
screens.forEach((s, i) => {
  const single = `<!DOCTYPE html>
<html lang="zh-CN"${perGround}><head><meta charset="UTF-8"><title>${htmlEsc(s.label)}</title>
<style>${styleCss}
html,body{margin:0;padding:0;width:380px;height:600px;overflow:hidden;background:var(--bg,var(--pg))}
.shell-bar,#proto-wrap{display:none !important}
.screen,.scr{position:relative !important;display:flex !important;width:380px;height:600px}
</style></head><body>${sprite}${s.inner}</body></html>`;
  const fn = path.join(dir, `${String(i + 1).padStart(2, '0')}-${s.id}.html`);
  fs.writeFileSync(fn, single);
});
console.log(`  per-screen -> ${dir}/ (${screens.length} files)`);
