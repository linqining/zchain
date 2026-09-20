// =============================================================================
// extension/tests/prd_static_guards.test.js
//
// PRD《方向 B 账簿》§9 / §10 里**只能靠静态核查保证**的那一类验收：
// 一次函数调用看不到，必须扫源码与样式表才能确认。
//
// 这一版是奔着 R-21 去的：稿面声明「2,349 个节点逐元素取色 · 0 项不达标」
// 与「纵向容量比方向 A 多约 25%」都**无法由稿面数字复算**，PRD 因此要求
// 「自检脚本入库并纳入 CI；或从稿中删除该量化声明」。本文件就是那个脚本——
// 对比度按 WCAG 1.4.3 从 `popup.css` 的 token 现算，不再引用稿面结论。
//
// 同时它兜住一批"改了代码才会发现"的结构性回归：CSP 内联事件、webfont、
// console 泄露、未 import 的跨模块调用、`$` 法币字面量、盾牌类徽章。
// =============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const EXT = path.resolve(HERE, '..');
const read = (rel) => readFileSync(path.join(EXT, rel), 'utf8');

const CSS = read('popup/popup.css');
const POPUP_HTML = read('popup/popup.html');
const POPUP_JS = read('popup/popup.js');
const SW_JS = read('background/service_worker.js');
const MANIFEST = JSON.parse(read('manifest.json'));

// ---------------------------------------------------------------------------
// WCAG 1.4.3 相对亮度与对比度（脚本自足，不引第三方）
// ---------------------------------------------------------------------------

/** 解析 :root 与 [data-ground] 块里的 `--name: #hex;` token。 */
function cssVars(css) {
  const out = new Map();
  for (const m of css.matchAll(/(--[a-z0-9-]+)\s*:\s*(#[0-9a-fA-F]{3,8})\s*;/g)) {
    if (!out.has(m[1])) out.set(m[1], m[2]); // 先出现者 = 纸白底（默认态）
  }
  return out;
}

function rgb(hex) {
  let h = hex.replace('#', '');
  if (h.length === 3) h = h.split('').map((c) => c + c).join('');
  h = h.slice(0, 6);
  return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16) / 255);
}

function relLuminance(hex) {
  const [r, g, b] = rgb(hex).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

/** WCAG 对比度：(L1 + 0.05) / (L2 + 0.05)，保留两位。 */
export function contrastRatio(fg, bg) {
  const a = relLuminance(fg);
  const b = relLuminance(bg);
  const [hi, lo] = a >= b ? [a, b] : [b, a];
  return Math.round(((hi + 0.05) / (lo + 0.05)) * 100) / 100;
}

/**
 * 去掉注释后的源码。字符串内容检查必须在**去注释**的源码上做：否则一句
 * 「不得使用盾牌=安全保证的视觉暗示」这类解释性注释会把自检脚本自己绊倒，
 * 而这类误报会让人直接删掉脚本——比不检查更糟。
 */
function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`\\])\/\/[^\n]*/g, '$1');
}
const POPUP_CODE = stripComments(POPUP_JS);

const VARS = cssVars(CSS);

test('R-21 自检脚本可复算：token 表能被解析出纸白底前景/背景色对', () => {
  for (const name of ['--ink', '--ink-2', '--ink-3', '--pg', '--cd', '--felt', '--bad', '--amb', '--real', '--play']) {
    assert.equal(VARS.has(name), true, `缺少 token ${name}，无法复算对比度`);
  }
});

test('R-21 / §9 正文对比度全部 ≥4.5:1（纸白底，逐项现算不引用稿面结论）', () => {
  const bodyPairs = [
    ['正文 ink / 纸白 pg', '--ink', '--pg'],
    ['次级 ink-2 / 纸白 pg', '--ink-2', '--pg'],
    ['三级 ink-3 / 纸白 pg', '--ink-3', '--pg'],
    ['正文 ink / 卡片 cd', '--ink', '--cd'],
    ['次级 ink-2 / 卡片 cd', '--ink-2', '--cd'],
    ['三级 ink-3 / 卡片 cd', '--ink-3', '--cd'],
    ['felt 绿 / 纸白 pg', '--felt', '--pg'],
    ['bad 朱红 / 纸白 pg', '--bad', '--pg'],
    ['amb 琥珀 / 纸白 pg', '--amb', '--pg'],
    ['real 金墨 / 纸白 pg', '--real', '--pg'],
    ['play 蓝墨 / 纸白 pg', '--play', '--pg'],
  ];
  const failures = [];
  for (const [label, fg, bg] of bodyPairs) {
    const ratio = contrastRatio(VARS.get(fg), VARS.get(bg));
    if (ratio < 4.5) failures.push(`${label} = ${ratio}:1 < 4.5:1（${fg} on ${bg}）`);
  }
  assert.deepEqual(failures, [], `以下正文配对未达 AA：\n${failures.join('\n')}`);
});

test('§9 ink-3 压深后的最紧一对仍 ≥4.5（PRD D-83 的过程记录可复算）', () => {
  const tight = contrastRatio(VARS.get('--ink-3'), VARS.get('--pg-2'));
  assert.ok(tight >= 4.5, `ink-3 / pg-2 = ${tight}:1，稿面称已压深到 4.85，须仍能达标`);
});

test('§9 反色条（墨底反色）在两种底色下都可读', () => {
  assert.ok(contrastRatio(VARS.get('--on-ink'), VARS.get('--ink')) >= 4.5);
});

// ---------------------------------------------------------------------------
// 品牌硬规则与 CSP（违反即界面事故，PRD §1.3 要求各为 0）
// ---------------------------------------------------------------------------

test('品牌硬规则 1：零 webfont（全文件不得出现 @font-face）', () => {
  assert.equal(CSS.includes('@font-face'), false);
  assert.equal(POPUP_HTML.includes('@font-face'), false);
  assert.equal(/fonts\.(googleapis|gstatic)/.test(POPUP_HTML + CSS), false);
});

test('MV3 script-src self：HTML 与 JS 均不得产生内联事件处理器', () => {
  assert.equal(/\son(click|input|change|submit|keydown)\s*=/i.test(POPUP_HTML), false);
  // JS 侧用属性赋值形式装配事件（`.onclick =`）同样绕开委托，禁止。
  assert.equal(/\.on(click|input|change|submit)\s*=/.test(POPUP_JS), false);
  assert.equal(/javascript:/.test(POPUP_HTML), false);
  assert.equal(MANIFEST.content_security_policy.extension_pages.includes("script-src 'self'"), true);
});

test('WALLET-ACC-4：popup 不使用 console 输出请求内容', () => {
  assert.equal(/\bconsole\.(log|info|debug|warn|error)\s*\(/.test(POPUP_JS), false);
});

test('权限最小化：只申请 storage + alarms，host 权限限本机', () => {
  assert.deepEqual(MANIFEST.permissions.sort(), ['alarms', 'storage']);
  for (const host of MANIFEST.host_permissions) {
    assert.ok(/^http:\/\/(localhost|127\.0\.0\.1)/.test(host), `host 权限越界：${host}`);
  }
  assert.equal(MANIFEST.permissions.includes('tabs'), false);
  assert.equal(MANIFEST.permissions.includes('<all_urls>'), false);
});

test('AC-01 结构性：popup 源码里不存在法币金额字面量', () => {
  // 允许的唯一 `$` 是模板字符串插值与 `'$' + …` 的受控分支，不允许 `$1,234.56` 形态。
  const literals = POPUP_CODE.match(/['"`]\s*\$[\d,]+\.\d{2}\s*['"`]/g) ?? [];
  assert.deepEqual(literals, [], `发现硬编码法币字面量：${literals.join(', ')}`);
  assert.equal(/\$22,288|\$8,124|\$4,043|\$10,120/.test(POPUP_CODE + CSS + POPUP_HTML), false);
});

test('AC-34：界面不引用盾牌类徽章图形', () => {
  assert.equal(/ic\(['"]shield['"]|icon: 'shield'/.test(POPUP_CODE), false, 'shield 图形不得用于任何界面位置');
  // 禁止的是**肯定式**审计承诺；PRD F-19 规则 4 反过来**强制**要求一句
  // 反向声明（含「不等于已审计」），所以不能笼统禁掉"已审计"三个字。
  for (const banned of ['审计通过', '已通过审计', '已通过第三方审计', 'audited']) {
    assert.equal(POPUP_CODE.includes(banned), false, `不得出现「${banned}」`);
  }
  // 「安全保证」只允许出现在**否定式**里——AC-32 反过来要求界面明说
  // "限额不是安全保证"，所以笼统禁词会把合规文案禁掉。
  const guarantee = (POPUP_CODE.match(/.{0,6}安全保证/g) ?? []).filter((ctx) => !/不|非|未|无/.test(ctx));
  assert.deepEqual(guarantee, [], `出现肯定式安全承诺：${guarantee.join(' / ')}`);
  assert.equal(/不是安全保证/.test(POPUP_CODE), true, 'AC-32：限额必须被否定为安全保证');
  assert.equal(POPUP_CODE.includes('未通过第三方审计'), true, '关于段必须常驻反向声明');
  assert.equal(POPUP_CODE.includes('不等于已审计'), true, '必须说明「可验证 ≠ 已审计」');
});

test('AC-26 / R-32：任何位置不得声称链上已验证', () => {
  for (const banned of ['链上已验证', 'on-chain verified', '链上验证通过']) {
    assert.equal((POPUP_CODE + CSS).includes(banned), false, `不得出现「${banned}」（zk_verify 目前是 Stub）`);
  }
});

test('R-15：界面不得把凭证到位说成可提现', () => {
  const blob = POPUP_CODE;
  // 允许「不可提现 / 不暗示可提现」这类型否定句，禁止裸的肯定式「可提现」。
  // 允许否定式（不可提现 / 不暗示可提现 / 非可提现），禁止裸肯定式。
  const offenders = (blob.match(/.{0,4}可提现/g) ?? [])
    .filter((ctx) => !/不|非|未|无/.test(ctx.slice(0, 3)));
  assert.deepEqual(offenders, [], `发现"可提现"式表述：${offenders.join(', ')}`);
});

test('R-17 / AC-03：收款路径不画伪二维码图形', () => {
  const recvSheetBlock = POPUP_JS.slice(POPUP_JS.indexOf('function recvSheet'), POPUP_JS.indexOf('function mount'));
  assert.equal(/ic\(['"]qr['"]/.test(recvSheetBlock), false, 'sheet 内不得出现二维码图形');
  assert.equal(recvSheetBlock.includes('二维码未接入'), true);
  assert.equal(POPUP_JS.includes('word-break:break-all'), true, '收款地址必须完整可换行展示');
});

// ---------------------------------------------------------------------------
// §7 动效规范落地（此前 0 个 @keyframes / 0 处 prefers-reduced-motion）
// ---------------------------------------------------------------------------

test('§7 A-5：存在 prefers-reduced-motion 降级块，且时长降到 0.01ms', () => {
  const blocks = CSS.match(/@media\s*\(prefers-reduced-motion:\s*reduce\)\s*{[\s\S]*?}\s*}/g) ?? [];
  assert.ok(blocks.length >= 1, '缺少 prefers-reduced-motion 块');
  assert.equal(/animation-duration:\s*0\.01ms/.test(blocks.join('')), true);
  assert.equal(/transition-duration:\s*0\.01ms/.test(blocks.join('')), true);
});

test('§7.2：逐场景动效所需关键帧均已定义', () => {
  const need = ['qEnter', 'qFade', 'qSheetUp', 'qModalPop', 'qSeal', 'qRail', 'qSpin', 'qPulse', 'qNudge'];
  const declared = new Set((CSS.match(/@keyframes\s+([A-Za-z0-9_-]+)/g) ?? []).map((x) => x.replace('@keyframes ', '')));
  for (const k of need) assert.ok(declared.has(k), `缺少 @keyframes ${k}`);
});

test('§7.3 禁止清单：不做 scroll-driven 动画、不做 count-up', () => {
  assert.equal(/animation-timeline|scroll\(\)|@scroll-timeline/.test(CSS), false);
  assert.equal(/ScrollTimeline|IntersectionObserver/.test(POPUP_JS), false);
  // 数字滚动增长（count-up）中间帧会显示错误金额
  assert.equal(/requestAnimationFrame[\s\S]{0,200}(amount|balance)/i.test(POPUP_JS), false);
});

test('§7.3：未实现能力不给"可点"笔触——ForceInclude 保持禁用', () => {
  assert.equal(POPUP_JS.includes("'ForceInclude 未开放'"), true);
  assert.match(POPUP_JS, /ForceInclude 未开放[\s\S]{0,200}disabled: true/);
});

// ---------------------------------------------------------------------------
// 模块契约：popup 里调用的每个跨模块导出名都必须真的被 import
// （`node --check` 抓不到 ReferenceError，本用例能）
// ---------------------------------------------------------------------------

const MODULES = {
  '../common/ui_ledger.js': 'common/ui_ledger.js',
  '../common/telemetry.js': 'common/telemetry.js',
  '../common/capability_matrix.js': 'common/capability_matrix.js',
  '../common/receipts.js': 'common/receipts.js',
  '../common/sessions.js': 'common/sessions.js',
  '../common/assets.js': 'common/assets.js',
  '../common/portal.js': 'common/portal.js',
};

async function exportedNames(rel) {
  return Object.keys(await import(path.join(EXT, rel)));
}

test('模块契约：popup.js 调用的跨模块导出名全部已 import', async () => {
  const importBlocks = POPUP_JS.match(/import\s*\{[\s\S]*?\}\s*from\s*'\.\.\/common\/[^']+';/g) ?? [];
  const imported = new Set(
    importBlocks
      .flatMap((b) => b.replace(/import\s*\{/, '').replace(/\}\s*from[\s\S]*/, '').split(','))
      .map((x) => x.replace(/\s+as\s+\S+$/, '').trim())
      .filter(Boolean),
  );
  assert.ok(imported.has('assetBadge'), '别名剥离不得吃掉含 "as" 的名字（如 assetBadge）');
  const problems = [];
  for (const [, rel] of Object.entries(MODULES)) {
    for (const name of await exportedNames(rel)) {
      const called = new RegExp(`(?<![\\w$.])${name}\\s*\\(`).test(POPUP_CODE);
      if (called && !imported.has(name)) problems.push(`${name}（来自 ${rel}）被调用但未 import`);
    }
  }
  assert.deepEqual(problems, [], `运行时会抛 ReferenceError：\n${problems.join('\n')}`);
});

test('模块契约：service worker 同样不存在"调用未导入的导出名"', async () => {
  const importBlocks = SW_JS.match(/import\s*\{[\s\S]*?\}\s*from\s*'[^']+';/g) ?? [];
  const imported = new Set(
    importBlocks
      .flatMap((b) => b.replace(/import\s*\{/, '').replace(/\}\s*from[\s\S]*/, '').split(','))
      .map((x) => x.replace(/\s+as\s+\S+$/, '').trim())
      .filter(Boolean),
  );
  const problems = [];
  for (const [, rel] of Object.entries(MODULES)) {
    for (const name of await exportedNames(rel)) {
      const called = new RegExp(`(?<![\\w$.])${name}\\s*\\(`).test(SW_JS);
      if (called && !imported.has(name)) problems.push(`${name}（来自 ${rel}）被调用但未 import`);
    }
  }
  assert.deepEqual(problems, [], `SW 运行时会抛 ReferenceError：\n${problems.join('\n')}`);
});

test('§6.3 格式化单一出口：popup 不再本地拼装千分位/倒计时/相对时间', () => {
  assert.equal(/\.toLocaleString\(\s*\{[^}]*useGrouping/.test(POPUP_JS), false, '千分位必须走 fmtAmount/fmtDisplay');
  assert.equal(/toFixed\(\s*2\s*\)\s*\+\s*['"]s['"]/.test(POPUP_JS), false, '倒计时必须走 remainText');
  assert.equal(/['"]昨天['"]/.test(POPUP_JS), false, '「昨天」不是 relTime 的任何输出（§13 C-10）');
  // 剩余时间（TTL/倒计时）必须走 remainText；耗时读数（1.72s）不在此列。
  assert.equal(/expiresAt[^\n]*?\}s`/.test(POPUP_JS), false, '剩余时间不得手工拼 s 后缀');
});

test('§3.2 屏幕注册表：18 条屏幕都有渲染器与 tab 归属', () => {
  const { SCREENS } = { SCREENS: [...POPUP_JS.matchAll(/RENDERERS(?:\.|\[')([a-z0-9-]+)/g)].map((m) => m[1]) };
  const unique = new Set(SCREENS);
  assert.ok(unique.size >= 18, `渲染器数量 ${unique.size} 少于注册表 18 条`);
  const { SCREENS: registry } = {}; // 注册表本身由 ui_ledger 单测覆盖，这里只查 id 对齐
  void registry;
  for (const id of ['welcome', 'success', 'import', 'lock', 'home', 'acct', 'zc-send', 'zc-withdraw', 'zc-confirm', 'zc-sessions', 'zc-portal', 'zc-receipts', 'send', 'contract', 'history', 'manage', 'proofs', 'settings']) {
    assert.equal(unique.has(id), true, `屏幕 ${id} 缺渲染器`);
  }
});

test('R-40 / AC-45：快捷动作条吸底（13 屏超 600px 的缓解）', () => {
  // 取**所有** .acts 规则块：文件里还有一条布局用的 .acts，必须逐条看。
  const blocks = CSS.match(/\.acts\s*\{[^}]*\}/g) ?? [];
  assert.ok(blocks.some((b) => /position:\s*sticky/.test(b) && /bottom:\s*0/.test(b)), '.acts 必须有一条吸底规则');
});

// ---------------------------------------------------------------------------
// 界面侧文案与门槛的源码断言（这些 AC 属"文案即验收"，静态可钉）
// ---------------------------------------------------------------------------

test('AC-33 / F-21：撤销会话密钥必须键入 REVOKE，且三条后果写全', () => {
  assert.match(POPUP_CODE, /gatedInput\('revoke-confirm'[^)]*token: 'REVOKE'/);
  assert.match(POPUP_CODE, /typed !== 'REVOKE'/);
  const modal = POPUP_CODE.slice(POPUP_CODE.indexOf("act('session-revoke'"), POPUP_CODE.indexOf("act('session-revoke-confirm'"));
  for (const need of ['立即生效', '永久失效', '需重新输入口令']) {
    assert.equal(modal.includes(need), true, `撤销模态缺「${need}」`);
  }
});

test('AC-08 / R-07：策略型不可提交原因必须带「本版本不会开放」限定语', () => {
  assert.equal(POPUP_CODE.includes('本版本不会开放'), true);
  assert.equal(POPUP_CODE.includes('cannotSubmitReasonDetails'), true, '限定语必须来自数据，而非界面猜文本');
  const wp = read('common/withdraw_preview.js').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`\\])\/\/[^\n]*/g, '$1');
  assert.match(wp, /'policy'\)/, 'withdraw_preview 必须产出 policy 型原因');
  assert.match(wp, /'data'\)/, '并区分 data 型原因');
});

test('AC-31 / R-31：会话密钥页明写按 UTC 日重置', () => {
  assert.equal(POPUP_CODE.includes('DAILY_RESET_TEXT'), true);
});

test('R-42：区分 SNIP-12 授权会话与 15 分钟解锁会话', () => {
  assert.match(POPUP_CODE, /两个"会话"不是一回事/);
});

test('AC-47 / R-19：Starknet 层不得回落 ETH 符号', () => {
  assert.equal(/tokenSymbol\s*\?\?\s*'ETH'/.test(POPUP_CODE), false, '禁止 `?? \'ETH\'` 式 fail-open');
  // 只约束 Starknet pane：EVM pane 用 Ξ 是准确的。
  const stkPaneSrc = POPUP_CODE.slice(POPUP_CODE.indexOf('async function stkPane'), POPUP_CODE.indexOf("act('stk-faucet'"));
  assert.equal(stkPaneSrc.includes("tk: 'Ξ'"), false, 'Starknet pane 不得使用以太坊数值符号');
  assert.equal(/\?\?\s*'ETH'/.test(stkPaneSrc), false);
});

test('AC-36：能力矩阵由 CAPABILITY_ROWS 单一常量渲染', () => {
  assert.equal(POPUP_CODE.includes('for (const row of CAPABILITY_ROWS)'), true);
  assert.equal(POPUP_CODE.includes('CAP_RED_LINES'), false, '不得保留第二份硬编码清单');
});

test('R-11：回执上限说明常驻渲染', () => {
  assert.equal(POPUP_CODE.includes("capacityNotice('receipts')"), true);
});

test('R-36：凭证簿计数走 proofLogSummary，不留手写窗口文案', () => {
  assert.equal(POPUP_CODE.includes('proofLogSummary('), true);
  assert.equal(POPUP_CODE.includes('最近 24 小时'), false, '稿面的 24 小时窗口无实现来源');
});

test('R-24 / AC-27：回执行渲染金额、kind 标签与 evidence', () => {
  for (const call of ['receiptAmount(', 'receiptKindLabel(', 'receiptEvidenceText(']) {
    assert.equal(POPUP_CODE.includes(call), true, `回执行缺 ${call}`);
  }
});

test('AC-11：ladder mismatch 与凭证条曝光均有埋点出口', () => {
  assert.equal(POPUP_CODE.includes("track('proof_ladder_mismatch'"), true);
  assert.equal(POPUP_CODE.includes("track('proof_rail_view'"), true);
});

test('§6.4 埋点默认关闭且开关可见（用户可关闭）', () => {
  assert.match(POPUP_CODE, /createTelemetry\(\{ enabled: false/);
  assert.equal(POPUP_CODE.includes("act('toggle-telemetry'"), true);
  assert.equal(POPUP_CODE.includes('TELEMETRY_ENABLED_KEY'), true);
});

test('AC-44：减弱动效在 JS 侧也被尊重（不依赖 CSS 单独生效）', () => {
  assert.equal(POPUP_CODE.includes('prefersReducedMotion()'), true);
  assert.match(POPUP_CODE, /if \(prefersReducedMotion\(\)\) done\(\)/, '离场动画须可被降级为立即完成');
});

test('R-08：口令复制块带常驻风险警示', () => {
  assert.match(POPUP_CODE, /copyKind: 'password'/);
  assert.match(POPUP_CODE, /剪贴板[^'\n]{0,40}扩展/);
});

test('R-09：导入私钥输入默认掩码', () => {
  assert.match(POPUP_CODE, /input\('import-key',[^}]*type: 'password'/);
});

test('§9 字体：只用 system-ui / ui-monospace 栈', () => {
  assert.equal(/--mono:\s*['"]?(ui-monospace|Menlo|monospace)/.test(CSS) || /font-family:\s*var\(--mono\)/.test(CSS), true);
  assert.equal(/font-family:\s*(Inter|Roboto|Helvetica|Arial)/.test(CSS), false);
});
