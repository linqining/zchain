#!/usr/bin/env node
// =============================================================================
// run_08.mjs — 方向 B「账簿 / Ledger」UI 专属流：真实浏览器 E2E
//
// 设计出处：design/zchain-wallet-ui-b-ledger.html v0.2。run_05/06 覆盖 EVM 与
// Starknet 的链上面，run_07 覆盖 onboarding；本文件覆盖**方向 B 特有的账簿
// 立场与红线**，全部通过真实 popup DOM 操作驱动：
//
//   A. 链=筛选器：三链共用一套账簿模板，切换器只换数据面；
//   B. 双库分栏与合计边界：GAME/REAL 永不轧差；无价格源 → 不出现法币数字；
//   C. PLAY 转账全链路：水龙头 → 贪心选币预览（含找零/守恒/凭证阶梯/签名摘要）
//      → 确认 → 回执登记（signed）；
//   D. 展示-签名一致性在**后台**复核：摘要被换 / note 不在库 → 拒签；
//   E. REAL 提现 fail-closed：canSubmit 恒 false + 提交按钮禁用 + 原因逐条；
//   F. 凭证阶梯（pending→soft→proven→finalized）作为一等组件出现在凭证簿；
//   G. Proof Portal 失败面如实呈现（网关不可达 → 第 1 步红 + 结论「未通过」）；
//   H. 双底色（纸白/夜场）与金额显隐是偏好且持久化，不改变任何数据；
//   I. 能力矩阵逐条说明红线（不为好看放宽）。
//
// 用法（repo 根目录）：node extension/tests/e2e/run_08.mjs
// 退出码：0 = 全部 PASS；1 = 存在 FAIL。
// =============================================================================

import { spawn } from 'node:child_process';
import { appendFileSync, existsSync, mkdtempSync, readdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const EXT_ROOT = path.resolve(HERE, '..', '..');
const OUT_JSON = path.join(HERE, 'e2e08_result.json');
const OUT_PNG = path.join(HERE, 'e2e08_screenshot.png');
const PROGRESS = path.join(HERE, 'e2e08_progress.log');

const OWNER = '02' + 'ab'.repeat(32); // 合法 hex33 收款 owner（非本账户）

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
  const profileDir = mkdtempSync(path.join(tmpdir(), 'zchain_e2e08_'));
  const dbgPort = 11000 + Math.floor(Math.random() * 30000);
  const chrome = spawn(chromeBin, [
    '--headless=new',
    `--remote-debugging-port=${dbgPort}`,
    `--user-data-dir=${profileDir}`,
    '--no-first-run', '--no-default-browser-check',
    `--load-extension=${EXT_ROOT}`,
    'about:blank',
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  let chromeErr = '';
  chrome.stderr.on('data', (d) => { chromeErr += d; });
  const cleanup = () => { try { chrome.kill('SIGKILL'); } catch { /* ignore */ } };
  process.on('exit', cleanup);
  process.on('SIGINT', () => { cleanup(); process.exit(130); });

  try {
    const devtools = `http://127.0.0.1:${dbgPort}`;
    let version = null;
    for (let i = 0; i < 100; i++) {
      try { version = await (await fetch(`${devtools}/json/version`)).json(); break; } catch { await sleep(300); }
    }
    if (!version) throw new Error(`DevTools 不可达:\n${chromeErr.slice(-1500)}`);

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

    const popupTarget = await newTarget(devtools, `${EXT}/popup/popup.html`);
    const page = await connectCdp(popupTarget, 'popup');
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
    /** 点击直到效果成立（popup.js 是 deferred module，首帧可能还没挂上监听）。 */
    async function nav(selector, effectExpr, timeoutMs = 20_000) {
      const t0 = Date.now();
      for (;;) {
        await page.eval(`document.getElementById(${JSON.stringify(selector)})?.click(); true`).catch(() => { });
        let ok = null;
        try { ok = await page.eval(effectExpr, 5_000); } catch { /* 重渲染瞬间 */ }
        if (ok) return ok;
        if (Date.now() - t0 > timeoutMs) return null;
        await sleep(300);
      }
    }
    const attr = (sel, name) => page.eval(`document.querySelector(${JSON.stringify(sel)})?.getAttribute(${JSON.stringify(name)}) ?? null`).catch(() => null);
    const bodyText = () => page.eval(`document.body.innerText`).catch(() => '');

    // ===== A0：引导（一键创建三层；自动口令只显一次）=====
    await nav('welcome-create-btn', `!!document.getElementById('welcome-success')`, 30_000);
    const gen0 = await waitForExpr(`(document.getElementById('welcome-generated-password')?.textContent ?? '').length >= 20 ? 'ok' : null`, 20_000);
    record('A0 一键创建三层 → 成功页自动口令只显一次', gen0 === 'ok');
    await nav('welcome-done-gate', `!document.getElementById('welcome-done-btn')?.disabled`);
    await nav('welcome-done-btn', `!!document.getElementById('home-card')`);

    // ===== A. 链=筛选器（一套模板 × 三链数据面）=====
    const onHome = await waitForExpr(`!!document.getElementById('home-card')`, 10_000);
    record('A1 首页 = 三链总账（账户层卡片 + 底部三 tab）', onHome === true);
    const onAcct = await nav('tab-acct', `!!document.getElementById('cs-zc')`, 20_000);
    record('A1b 账簿 tab = 带链切换器的账簿面板', onAcct === true);
    const toZc = await nav('cs-zc', `!!document.getElementById('zc-send') && document.getElementById('cs-zc')?.classList.contains('on')`);
    record('A2 切到 ZChain 链：账簿模板换 GAME/REAL 数据面', toZc === true);
    const toEvm = await nav('cs-evm', `!!document.getElementById('evm-address') && document.getElementById('cs-evm')?.classList.contains('on')`);
    record('A3 切到 EVM 链：同一屏结构、地址/余额面来自 EVM 层', toEvm === true);
    const toStk = await nav('cs-stk', `!!document.getElementById('stk-address') && document.getElementById('cs-stk')?.classList.contains('on')`);
    record('A4 切到 Starknet 链：模板不变、数据面换层', toStk === true);
    const backToZc = await nav('cs-zc', `!!document.getElementById('zc-send')`);
    const sharedHeader = await attr('.dh .dh-kind', 'class');
    record('A5 三链来回切换后抬头结构一致（票据头 + 齿孔线，未各写一份）', backToZc === true && sharedHeader === 'dh-kind');

    // ===== B. 合计边界与价格源诚实性（首页总账口径）=====
    await nav('tab-home', `!!document.getElementById('home-card')`);
    const heroText = await page.eval(`document.querySelector('.tot .tot-a')?.textContent ?? ''`);
    const homeTxt = await bodyText();
    record('B1 无价格源 → 合计显示占位而非编造法币数字', !/[¥$€]\s?[0-9]/.test(heroText) && heroText.includes('—'), String(heroText));
    record('B2 首页显式标注「价格源未接入」', homeTxt.includes('价格源未接入'));
    await nav('tab-acct', `!!document.querySelector('.split')`);
    const splitTxt = await nav('tab-acct', `!!document.querySelector('.split')`)
      ? await page.eval(`document.querySelector('.split')?.textContent ?? ''`) : '';
    record('B3 GAME / REAL 分栏展示（跨域金额不轧差）', /GAME/.test(splitTxt) && /REAL/.test(splitTxt), splitTxt.replace(/\n/g, ' | ').slice(0, 120));

    // ===== C. PLAY 转账全链路（水龙头 → 选币 → 签名 → 回执）=====
    await fill('faucet-amount', '500');
    await click('zc-faucet-btn');
    const faucetNote = await waitForExpr(`(() => {
      const t = document.body.innerText;
      return t.includes('500') && t.includes('PLAY') ? t : null;
    })()`, 25_000);
    record('C1 水龙头铸 500 PLAY → 账面即时反映', !!faucetNote);

    await nav('zc-send', `!!document.getElementById('zc-send-amount')`);
    await fill('zc-send-amount', '200');
    await fill('zc-send-owner', OWNER);
    await click('zc-send-preview');
    const previewCard = await waitForExpr(`(() => {
      const t = document.body.innerText;
      return t.includes('贪心选币') && t.includes('找零') && t.includes('守恒核对') ? t : null;
    })()`, 20_000);
    record('C2 转账预览：选币 + 找零 + 守恒三行齐全（note 全额消费）', !!previewCard,
      String(previewCard).split('\n').filter((x) => /找零|守恒|消耗/.test(x)).join(' | ').slice(0, 160));
    // 摘要按 wallet-core ABI 约定是小写 hex（不带 0x 前缀）。
    const digestShown = await waitForExpr(`(() => {
      const t = (document.getElementById('zc-send-digest')?.textContent ?? '');
      return /^[0-9a-f]{8,}…[0-9a-f]{4,}$/i.test(t) ? t : null;
    })()`, 15_000);
    record('C3 摘要来自 wallet-core 预览（展示与签名同源）', !!digestShown, String(digestShown));
    const railOnSend = await waitForExpr(`document.querySelectorAll('#view .rail .rn').length >= 4 ? true : null`, 10_000);
    const ladderTxt = await page.eval(`document.querySelector('.rail-cap')?.textContent ?? ''`).catch(() => '');
    record('C4 凭证阶梯作为一等组件出现在转账预览（4 级 + 短板文案）',
      railOnSend === true && /短板/.test(ladderTxt), ladderTxt.replace(/\n/g, ' ').slice(0, 120));
    // 只读判定，不点击（点击即真签名；nav 会重复点击）。
    const confirmEnabled = await waitForExpr(`(() => {
      const b = document.getElementById('zc-send-confirm');
      return b && b.disabled === false ? true : null;
    })()`, 15_000);
    record('C5 达标后「确认转账」解禁（devnet 门槛=soft，见策略注释）', confirmEnabled === true);
    await click('zc-send-confirm');
    const receiptAfter = await waitForExpr(`(() => {
      const rows = document.querySelectorAll('#view .tx').length;
      return rows >= 1 && document.body.innerText.includes('signed') ? rows : null;
    })()`, 25_000);
    record('C6 确认 → 签名成功并登记回执（状态位 signed）', !!receiptAfter, `rows=${receiptAfter}`);
    const rcBuckets = await waitForExpr(`(() => {
      const a = document.getElementById('rc-seg-all')?.textContent ?? '';
      const p = document.getElementById('rc-seg-pend')?.textContent ?? '';
      return /全部 1/.test(a) && /未上链 1/.test(p) ? a + ' / ' + p : null;
    })()`, 15_000);
    record('C7 回执分桶：全部 1 / 未上链 1（投递状态机）', !!rcBuckets, String(rcBuckets));

    // ===== D. 展示-签名一致性在后台复核（绕过 UI 直发 RPC 也拒）=====
    // 在途支出软锁（pendingSpendMap）：C2 确认的 200 转账已占用其输入 note
    // （inclusion 前不可再花）——先补水一张，后台双闸验证才有可签的 operation。
    await msg({ type: 'popup:faucet', amount: '100' });
    await waitForExpr(`(async () => { try {
      const r = await chrome.runtime.sendMessage({ type: 'popup:getNotes' });
      return (r?.notes ?? []).filter((n) => n.spendable !== false).length >= 1 ? 'ok' : null;
    } catch { return null; } })()`, 25_000);
    const pv = await msg({ type: 'popup:transferPreview', amount: '100', owner: OWNER });
    const badDigest = await msg({ type: 'popup:transferConfirm', operation: pv?.preview?.operation, digest: '00'.repeat(32) });
    record('D1 摘要被换 → PreviewMismatch（不签）', badDigest?.error?.code === 'PreviewMismatch', JSON.stringify(badDigest).slice(0, 120));
    const forged = JSON.parse(JSON.stringify(pv?.preview?.operation ?? {}));
    forged.inputs = ['f'.repeat(64)];
    const badNote = await msg({ type: 'popup:transferConfirm', operation: forged, digest: pv?.preview?.digest ?? '' });
    record('D2 输入 note 不在库 → NoteNotFound（第二道闸在后台）',
      badNote?.error?.code === 'NoteNotFound', JSON.stringify(badNote).slice(0, 140));
    const realNoteOnly = await msg({ type: 'popup:transferPreview', amount: '100', owner: OWNER });
    record('D3 预览本身可提交判定与门槛一致（requiredProof 随网络形态）',
      realNoteOnly?.preview?.finality?.requiredProof === 'soft' && realNoteOnly?.preview?.canSubmit === true,
      JSON.stringify(realNoteOnly?.preview?.finality));

    // ===== E. REAL 提现 fail-closed =====
    await nav('sub-back', `!!document.getElementById('zc-withdraw')`);
    await nav('zc-withdraw', `!!document.getElementById('wd-amount')`);
    await fill('wd-amount', '1');
    await fill('wd-owner', OWNER);
    await click('wd-preview');
    const wdReasons = await waitForExpr(`(() => {
      const t = document.body.innerText;
      return t.includes('暂不可提交') ? t : null;
    })()`, 20_000);
    record('E1 REAL 提现预览：逐条列出不可提交原因', !!wdReasons,
      String(wdReasons).split('\n').filter((x) => /REAL 库为空|vault_offline|finality|不足/.test(x)).join(' | ').slice(0, 160));
    const submitDisabled = await page.eval(`!!document.getElementById('wd-submit')?.disabled`);
    const canSubmitFlag = await page.eval(`(async () => { const r = await chrome.runtime.sendMessage({type:'popup:withdrawPreview', amount:'1', owner:${JSON.stringify(OWNER)}}); return r?.preview?.canSubmit === false; })()`);
    record('E2 提交按钮恒禁用 + 后台 canSubmit 恒 false（双层同结论）',
      submitDisabled === true && canSubmitFlag === true, `disabled=${submitDisabled} canSubmitFalse=${canSubmitFlag}`);

    // ===== F. 凭证簿（proof 阶梯提为一等 tab）=====
    await nav('sub-back', `!!document.getElementById('tab-proofs')`);
    await nav('tab-proofs', `!!document.getElementById('view')`);
    const proofsOk = await waitForExpr(`(() => {
      const t = document.body.innerText;
      return t.includes('凭证') && document.querySelectorAll('#view .rail .rn').length >= 4 ? t : null;
    })()`, 15_000);
    record('F1 凭证簿：阶梯组件 + note 级凭证计数（解锁后可见）', !!proofsOk,
      String(proofsOk).split('\n').filter((x) => /已达|短板|阶梯|note 带凭证/.test(x)).join(' | ').slice(0, 140));
    const twoStateMachines = await page.eval(`(() => {
      const t = document.body.innerText;
      return t.includes('signed → seen → included') && t.includes('pending → soft → proven → finalized') ? true : false;
    })()`).catch(() => false);
    record('F2 两套状态机并列说明（投递 vs 凭证，笔触不混用）', twoStateMachines === true);

    // ===== G. Proof Portal 失败面（网关不可达 → 如实标红）=====
    await msg({ type: 'popup:setGateway', chainId: (await msg({ type: 'popup:getState' }))?.chainId, gatewayUrl: 'http://127.0.0.1:9' });
    await nav('tab-acct', `!!document.getElementById('zc-portal')`);
    await sleep(200);
    await nav('zc-portal', `!!document.getElementById('portal-binding')`);
    await fill('portal-binding', 'ab'.repeat(32));
    await click('portal-verify');
    const portalFail = await waitForExpr(`(() => {
      const t = document.body.innerText;
      return /Gateway|不可达|超时|未配置/.test(t) && document.getElementById('portal-step-0')?.classList.contains('bad') ? t : null;
    })()`, 25_000);
    record('G1 网关不可达 → 第 1 步标红 + 错误码原样呈现（不伪造结论）', !!portalFail,
      String(portalFail).split('\n').filter((x) => /Gateway|不可达|超时/.test(x)).slice(0, 2).join(' | ').slice(0, 160));
    const sealBad = await page.eval(`(() => {
      const s = document.querySelector('.seal');
      return s ? s.textContent + '|' + s.className : null;
    })()`);
    record('G2 结论印章为「未通过」（fail-closed：任一阶段失败即非 verified）',
      /未通过/.test(String(sealBad)) && /seal-bad/.test(String(sealBad)), String(sealBad));

    // ===== H. 双底色 + 金额显隐（偏好，不改数据）=====
    const groundBefore = await attr('html', 'data-ground');
    await nav('sub-back', `!!document.getElementById('tab-home')`);
    await nav('tab-home', `!!document.getElementById('toggle-amount')`);
    await nav('hdr-settings', `!!document.getElementById('set-ground')`);
    await click('set-ground');
    const groundAfter = await attr('html', 'data-ground');
    const persisted = await page.eval(`localStorage.getItem('zchain.ui.ground')`);
    record('H1 双底色切换生效且持久化（纸白 ↔ 夜场）',
      groundBefore === 'paper' && groundAfter === 'night' && persisted === 'night', `${groundBefore}→${groundAfter} stored=${persisted}`);
    await click('set-hide');
    // 显隐作用在金额上：首页账户层行的 PLAY/NATIVE 数字变 ••••
    const hidden = await nav('sub-back', `document.getElementById('home-card')?.textContent?.includes('••••') ? true : null`);
    const hidePersisted = await page.eval(`localStorage.getItem('zchain.ui.hideAmount')`);
    record('H2 金额显隐只影响展示且持久化（余额数据本身不变）',
      hidden === true && hidePersisted === '1', `hidden=${hidden} stored=${hidePersisted}`);
    // 恢复默认（纸白主底色 + 金额可见），后续截图用设计主底色
    await nav('hdr-settings', `!!document.getElementById('set-hide')`);
    await click('set-hide');
    await click('set-ground');

    // ===== I. 能力矩阵（红线逐条）=====
    await click('set-capability');
    // 矩阵正文异步加载（先「加载中…」再填）：等内容出现，不把占位当结论。
    const capTxt = await waitForExpr(`(() => {
      const t = document.getElementById('cap-body')?.innerText ?? '';
      return t.includes('加载中') ? null : t;
    })()`, 15_000);
    record('I1 能力矩阵如实列出各层红线',
      /canSubmit 恒 false/.test(String(capTxt)) && /mainnet/.test(String(capTxt)),
      String(capTxt).replace(/\n/g, ' | ').slice(0, 180));
    const noAudit = (await bodyText()).includes('未通过第三方审计');
    record('I2 不出现审计徽章：未审计这件事写在界面上', noAudit === true);

    // ===== 截图（首页 · 恢复纸白底 + 金额可见之后）=====
    await nav('sub-back', `!!document.getElementById('home-card')`);
    await sleep(600);
    const shot = await Promise.race([
      page.send('Page.captureScreenshot', { format: 'png' }),
      new Promise((_, rej) => setTimeout(() => rej(new Error('screenshot timeout')), 10_000)),
    ]);
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
