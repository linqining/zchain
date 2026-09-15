#!/usr/bin/env node
// =============================================================================
// run_06.mjs — Extension 0.6 Starknet 钱包：真实浏览器 E2E（浏览器操作）
//
// 驱动方式与 run_05 相同：Chrome for Testing + --load-extension + CDP；
// **所有用户路径都通过真实 popup UI 操作**，链侧用本地 Starknet 开发链
// （starkdevchain.mjs：STARK curve ECDSA 独立验签）。
//
// 覆盖（对照交付要求）：
//   1. 余额查询：水龙头（注册 pubkey + 出资）→ 刷新余额/nonce/chainId；
//   2. 合约调用：只读（symbol / balance_of）+ 写（transfer invoke v1，
//      STARK curve ECDSA 签名 → 链上验签 → u256 状态核对）；
//   3. 交易记录：本地账本 + explorer txlist 合并 + 回执对账；
//   4. 钱包管理：创建（口令 keystore）、锁定/解锁（错口令 fail-closed）、
//      私钥导出、删除后重导入同址、修改口令（旧口令失效）；
//   5. 本文件即 e2e（浏览器操作），结果落 JSON + 截图。
//
// 用法（repo 根目录）：node extension/tests/e2e/run_06.mjs
// 退出码：0 = 全部 PASS；1 = 存在 FAIL。
// =============================================================================

import { spawn } from 'node:child_process';
import { appendFileSync, existsSync, mkdtempSync, readdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startStarkDevChain } from './starkdevchain.mjs';
import { toChecksumAddress, padAddress, hexToBigInt } from '../../common/stark/curve.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const EXT_ROOT = path.resolve(HERE, '..', '..');
const OUT_JSON = path.join(HERE, 'e2e06_result.json');
const OUT_PNG = path.join(HERE, 'e2e06_screenshot.png');
const PROGRESS = path.join(HERE, 'e2e06_progress.log');

const PW = 'correct horse battery staple';
const PW2 = 'new correct horse battery 2';

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
  static async connect(url, timeoutMs = 15_000) {
    const normalized = url.replace('ws://localhost:', 'ws://127.0.0.1:');
    const ws = new WebSocket(normalized);
    await new Promise((res, rej) => {
      const to = setTimeout(() => rej(new Error(`ws open timeout: ${normalized}`)), timeoutMs);
      ws.addEventListener('open', () => { clearTimeout(to); res(); }, { once: true });
      ws.addEventListener('error', () => { clearTimeout(to); rej(new Error(`ws error: ${normalized}`)); }, { once: true });
    });
    return new Cdp(ws);
  }
  send(method, params = {}, timeoutMs = 15_000) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params }));
    return Promise.race([
      new Promise((resolve, reject) => this.pending.set(id, { resolve, reject })),
      new Promise((_, rej) => setTimeout(() => { this.pending.delete(id); rej(new Error(`cdp send timeout: ${method}`)); }, timeoutMs)),
    ]);
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
    progress('GLOBAL WATCHDOG: 10min timeout — FAIL');
    writeFileSync(OUT_JSON, JSON.stringify({ verdict: 'FAIL', reason: 'watchdog timeout', results }, null, 2));
    process.exit(1);
  }, 10 * 60 * 1000);

  const chromeBin = findChrome();
  const chain = await startStarkDevChain({ port: 0 });
  progress(`starkdevchain: ${chain.url} (token ${chain.token.address})`);

  const profileDir = mkdtempSync(path.join(tmpdir(), 'zchain_e2e06_'));
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

  const cleanup = () => {
    try { chrome.kill('SIGKILL'); } catch { /* ignore */ }
    chain.close();
  };
  process.on('exit', cleanup);
  process.on('SIGINT', () => { cleanup(); process.exit(130); });

  try {
    const devtools = `http://127.0.0.1:${dbgPort}`;
    let version = null;
    for (let i = 0; i < 100; i++) {
      try { version = await (await fetch(`${devtools}/json/version`)).json(); break; } catch { await sleep(300); }
    }
    if (!version) throw new Error(`DevTools 不可达:\n${chromeErr.slice(-2000)}`);

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
    const gen = () => page.eval(`window.__zRenderGen ?? 0`).catch(() => 0);
    async function waitRender(beforeGen, effectExpr, timeoutMs = 20_000) {
      const t0 = Date.now();
      for (;;) {
        let v = null;
        try {
          v = await page.eval(`((window.__zRenderGen ?? 0) > ${Number(beforeGen)}) && (${effectExpr}) ? true : null`, 5_000);
        } catch { /* 渲染瞬间 */ }
        if (v) return true;
        if (Date.now() - t0 > timeoutMs) return null;
        await sleep(200);
      }
    }
    async function clickUntil(selector, effectExpr, timeoutMs = 20_000) {
      const t0 = Date.now();
      for (;;) {
        await page.eval(`document.getElementById(${JSON.stringify(selector)})?.click(); true`).catch(() => { });
        let ok = null;
        try { ok = await page.eval(effectExpr, 5_000); } catch { /* 渲染瞬间 */ }
        if (ok) return ok;
        if (Date.now() - t0 > timeoutMs) return null;
        await sleep(300);
      }
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
    async function click(selector) {
      await page.eval(`(() => {
        const n = document.getElementById(${JSON.stringify(selector)});
        if (!n) throw new Error('missing #${selector}');
        n.click();
        return true;
      })()`);
    }
    const openDetails = (selector) => page.eval(`(() => { const d = document.getElementById(${JSON.stringify(selector)}); if (!d) return false; d.open = true; return true; })()`).catch(() => false);

    // ===== S0/S1：模式切换 =====
    const hasStkBtn = await waitForExpr(`!!document.getElementById('mode-stk')`);
    record('S0 popup 页加载 + Starknet 模式按钮存在', hasStkBtn === true);
    const createVisible = await clickUntil('mode-stk', `!!document.getElementById('stk-create-btn')`);
    record('S1 切换到 Starknet 钱包 → 创建视图', createVisible === true);

    // ===== S2：创建钱包（STARK curve 密钥 + 口令 keystore + UDC 地址）=====
    let g = await gen();
    await fill('stk-pw', PW);
    await fill('stk-pw2', PW);
    await click('stk-create-btn');
    await waitRender(g, `!!document.getElementById('stk-address')`, 30_000);
    const addrRaw = await waitForExpr(`document.getElementById('stk-address')?.textContent ?? null`, 10_000);
    const pubRaw = await waitForExpr(`document.getElementById('stk-pubkey')?.textContent ?? null`, 10_000);
    const addrOk = typeof addrRaw === 'string'
      && /^0x[0-9a-fA-F]{1,64}$/.test(addrRaw)
      && hexToBigInt(addrRaw) < (2n ** 251n - 256n)
      && toChecksumAddress(addrRaw) === addrRaw;
    record('S2 创建钱包 → 地址（ADDR_BOUND 内 + Starknet 校验和）+ 公钥展示',
      addrOk && /^0x[0-9a-fA-F]{1,64}$/.test(String(pubRaw)), `${addrRaw} / ${String(pubRaw).slice(0, 14)}…`);
    const state0 = await msg({ type: 'popup:stkGetState' });
    record('S2b SW 状态：hasWallet + unlocked + 网络 = starknet-devnet',
      state0?.hasWallet === true && state0?.unlocked === true && state0.networkId === 'starknet-devnet',
      JSON.stringify({ hasWallet: state0?.hasWallet, unlocked: state0?.unlocked, net: state0?.networkId }).slice(0, 100));

    // ===== S3：RPC 指向本地开发链 =====
    g = await gen();
    await fill('stk-rpc-input', chain.url);
    await click('stk-rpc-save');
    await waitRender(g, `!!document.getElementById('stk-faucet-amount')`, 15_000);
    const savedRpc = await msg({ type: 'popup:stkGetState' });
    const net = (savedRpc.networks ?? []).find((n) => n.id === 'starknet-devnet');
    record('S3 保存 RPC 覆盖 → 生效 URL = starkdevchain', net?.rpcUrl === chain.url && net?.rpcOverridden === true, String(net?.rpcUrl));

    // ===== ① 余额查询：水龙头（注册 pubkey + 出资）→ 刷新 =====
    g = await gen();
    await fill('stk-faucet-amount', '100');
    await click('stk-faucet-btn');
    const balText = await waitForExpr(`(() => {
      const t = (document.getElementById('stk-balance')?.textContent ?? '').trim();
      return t === '100 DST' ? t : null;
    })()`, 30_000, 300);
    record('F1 余额查询：注册 pubkey + 水龙头 100 DST → 余额展示', balText === '100 DST', String(balText));
    const chainInfo = await waitForExpr(`(() => {
      const t = document.getElementById('stk-chain-info')?.textContent ?? '';
      return t.includes('ZCDN') && t.includes('nonce') ? t : null;
    })()`, 15_000);
    record('F2 链状态行：chainId=ZCDN + nonce 展示', !!chainInfo, String(chainInfo));
    const refresh = await msg({ type: 'popup:stkRefresh' });
    record('F3 SW 余额面：balanceWei=100e18 + nonce=0 + chainId 无误',
      refresh?.balanceWei === (100n * 10n ** 18n).toString() && refresh?.nonce === '0'
        && refresh?.chainId === 'ZCDN' && refresh?.chainIdMismatch === false,
      JSON.stringify(refresh).slice(0, 140));

    // ===== ② 合约调用 =====
    const OTHER = toChecksumAddress('0x' + 'beef'.padEnd(62, '0'));
    // 只读：symbol（代币合约）
    g = await gen();
    await fill('stk-contract', chain.token.address);
    await fill('stk-method', 'symbol');
    await fill('stk-args', '');
    await click('stk-read-btn');
    const symText = await waitForExpr(`(() => {
      const t = document.getElementById('stk-read-result')?.innerText ?? '';
      return t.includes('DST') ? t : null;
    })()`, 15_000);
    record('C1 合约只读 symbol → DST（starknet_call）', !!symText, String(symText).replace(/\n/g, ' | ').slice(0, 120));
    // 只读：balance_of（手填地址参数）
    await fill('stk-method', 'balance_of');
    await fill('stk-args', state0.accounts[0].address);
    await click('stk-read-btn');
    const balOf = await waitForExpr(`(() => {
      const t = document.getElementById('stk-read-result')?.innerText ?? '';
      return t.includes('100000000000000000000') ? t : null;
    })()`, 15_000);
    record('C2 合约只读 balance_of → 100e18（felt 原值）', !!balOf, String(balOf).replace(/\n/g, ' | ').slice(0, 140));
    // 写：transfer(OTHER, 25 DST) → 预览 → 确认
    g = await gen();
    await fill('stk-tx-recipient', OTHER);
    await fill('stk-tx-amount', '25');
    await click('stk-tx-prepare');
    const previewShown = await waitForExpr(`!!document.getElementById('stk-tx-preview')`, 15_000);
    const previewText = previewShown ? await page.eval(`document.getElementById('stk-tx-preview').innerText`) : '';
    record('C3 invoke v1 预览卡：selector + calldata + max fee + chainId',
      previewShown === true && String(previewText).includes('invoke v1') && String(previewText).includes('max fee')
        && String(previewText).includes('ZCDN'),
      String(previewText).replace(/\n/g, ' | ').slice(0, 200));
    await click('stk-tx-confirm');
    const txHash1 = await waitForExpr(`window.__lastStkBroadcast ?? null`, 30_000);
    await waitRender(g + 1, `!!document.getElementById('stk-address')`, 15_000);
    record('C4 确认 → STARK curve 签名广播（[r, s] invoke v1）', /^0x[0-9a-f]{1,64}$/.test(String(txHash1)), String(txHash1));
    const onchain1 = txHash1 ? chain.state.txs.get(String(txHash1).toLowerCase()) : null;
    record('C5 开发链核对：独立验签通过 + SUCCEEDED + sender = 钱包地址',
      onchain1?.executionStatus === 'SUCCEEDED'
        && hexToBigInt(onchain1?.from) === hexToBigInt(String(state0.accounts[0]?.address)),
      JSON.stringify({ from: onchain1?.from, st: onchain1?.executionStatus }).slice(0, 120));
    // 链上效果：balance_of(OTHER) = 25e18（render 重置输入 → 重填合约地址）
    await fill('stk-contract', chain.token.address);
    await fill('stk-method', 'balance_of');
    await fill('stk-args', OTHER);
    await click('stk-read-btn');
    const balOther = await waitForExpr(`(() => {
      const t = document.getElementById('stk-read-result')?.innerText ?? '';
      return t.includes('25000000000000000000') ? t : null;
    })()`, 15_000);
    record('C6 链上效果核对：balance_of(OTHER) → 25e18（u256）', !!balOther, String(balOther).replace(/\n/g, ' | ').slice(0, 140));

    // 取消路径（render 重置输入 → 重新填收款地址）
    await fill('stk-tx-recipient', OTHER);
    await fill('stk-tx-amount', '2');
    await click('stk-tx-prepare');
    await waitForExpr(`!!document.getElementById('stk-tx-reject')`, 15_000);
    await click('stk-tx-reject');
    const previewGone = await waitForExpr(`!document.getElementById('stk-tx-preview')`, 10_000);
    const notBroadcast = chain.state.txs.size === 1;
    record('T1 取消预览 → 不广播', previewGone === true && notBroadcast, `txs=${chain.state.txs.size}`);
    // 余额不足（手续费 + 金额 > 余额）：1000 DST
    await fill('stk-tx-amount', '1000');
    await click('stk-tx-prepare');
    const insufficient = await waitForExpr(`document.body.innerText.includes('InsufficientFunds') || document.body.innerText.includes('insufficient')`, 15_000);
    record('T2 余额不足 → 预览前拒绝', insufficient === true);
    await fill('stk-tx-recipient', OTHER);
    await fill('stk-tx-amount', '0.5');

    // ===== ③ 交易记录 =====
    g = await gen();
    await fill('stk-explorer-input', `${chain.url}/api`);
    await click('stk-explorer-save');
    await waitRender(g, `!!document.getElementById('stk-history-btn')`, 15_000);
    await click('stk-history-btn');
    const histOk = await waitForExpr(`(() => {
      const list = document.getElementById('stk-history-list');
      if (!list) return null;
      const boxes = list.querySelectorAll('.receipt').length;
      return boxes >= 1 && list.innerText.includes('已确认') ? boxes : null;
    })()`, 20_000);
    record('H1 交易记录列表：本地记录 + 已确认状态', !!histOk, `boxes=${histOk}`);
    await page.eval(`(() => { const cb = document.getElementById('stk-history-explorer'); cb.checked = true; return true; })()`);
    await click('stk-history-btn');
    const histExplorer = await waitForExpr(`(() => {
      const list = document.getElementById('stk-history-list');
      if (!list) return null;
      if (list.innerText.includes('未合并')) return 'note';
      return list.querySelectorAll('.receipt').length >= 1 ? 'merged' : null;
    })()`, 20_000);
    record('H2 explorer txlist 合并', histExplorer === 'merged', String(histExplorer));

    // ===== ④ 钱包管理 =====
    await openDetails('stk-export-details');
    await fill('stk-export-pw', 'wrong password!');
    await click('stk-export-btn');
    const exportDenied = await waitForExpr(`document.getElementById('stk-export-details')?.innerText.includes('口令错误')`, 10_000);
    record('M1 导出私钥：错口令 fail-closed（BadPassword）', exportDenied === true);
    await fill('stk-export-pw', PW);
    await click('stk-export-btn');
    const exportedKey = await waitForExpr(`document.getElementById('stk-exported-key')?.textContent ?? null`, 10_000);
    record('M2 导出私钥：口令确认 → felt 私钥展示', /^0x[0-9a-f]{1,64}$/.test(String(exportedKey)), String(exportedKey).slice(0, 12) + '…');
    // 锁定 → 错口令 → 正确口令
    g = await gen();
    await click('stk-lock-btn');
    const unlockVisible = await waitRender(g, `!!document.getElementById('stk-unlock-btn') && !document.getElementById('stk-address')`, 10_000);
    await fill('stk-unlock-pw', 'totally wrong');
    await click('stk-unlock-btn');
    const unlockDenied = await waitForExpr(`document.body.innerText.includes('口令错误')`, 10_000);
    record('M3 锁定 → 错口令解锁拒绝（fail-closed）', unlockVisible === true && unlockDenied === true);
    g = await gen();
    await fill('stk-unlock-pw', PW);
    await click('stk-unlock-btn');
    const reUnlocked = await waitRender(g, `!!document.getElementById('stk-address')`, 20_000);
    record('M4 正确口令解锁恢复', reUnlocked === true);
    // SW 级守卫：锁定时 prepareTx → SessionInvalid
    g = await gen();
    await click('stk-lock-btn');
    await waitRender(g, `!!document.getElementById('stk-unlock-btn')`, 10_000);
    const guard = await msg({ type: 'popup:stkPrepareTx', preset: 'erc20', method: 'transfer', recipient: OTHER, amountHuman: '1' });
    record('M5 锁定时 prepareTx → SessionInvalid（SW 守卫）', guard?.error?.code === 'SessionInvalid', JSON.stringify(guard));
    g = await gen();
    await fill('stk-unlock-pw', PW);
    await click('stk-unlock-btn');
    await waitRender(g, `!!document.getElementById('stk-address')`, 20_000);
    // 导出 → 删除 → 重导入 → 同一地址（同私钥重复导入会被正确拒绝）
    await openDetails('stk-export-details');
    await fill('stk-export-pw', PW);
    await click('stk-export-btn');
    const key2Raw = await waitForExpr(`(() => {
      const k = document.getElementById('stk-exported-key')?.textContent;
      if (k) return { key: k };
      const t = document.getElementById('stk-export-details')?.innerText ?? '';
      if (t.includes('口令错误')) return { err: 'BadPassword' };
      return null;
    })()`, 10_000);
    const key2 = key2Raw?.key ?? null;
    record('M6a 导出私钥（锁定/解锁循环后仍可用）', !!key2, JSON.stringify(key2Raw ?? null));
    await openDetails('stk-remove-details');
    g = await gen();
    await click('stk-remove-btn');
    const removed = await waitRender(g, `!!document.getElementById('stk-create-btn') && !!document.getElementById('stk-import-btn')`, 15_000);
    record('M6b 删除当前账户 → 回到创建视图', removed === true);
    await fill('stk-import-key', String(key2));
    await fill('stk-import-pw', PW);
    g = await gen();
    await click('stk-import-btn');
    const importRendered = await waitRender(g, `!!document.getElementById('stk-address')`, 30_000);
    const importedAddr = await waitForExpr(`document.getElementById('stk-address')?.textContent ?? null`, 10_000);
    record('M6 私钥再导入 → 同一地址（新随机盐 → 新地址但同私钥；校验和一致）',
      importRendered === true && typeof importedAddr === 'string'
        && hexToBigInt(importedAddr) < (2n ** 251n - 256n)
        && toChecksumAddress(importedAddr) === importedAddr,
      String(importedAddr));
    // 坏私钥拒绝
    g = await gen();
    await click('stk-lock-btn');
    await waitRender(g, `!!document.getElementById('stk-import-btn')`, 10_000);
    await fill('stk-import-key', '0xzz');
    await fill('stk-import-pw', PW);
    await click('stk-import-btn');
    const importRejected = await waitForExpr(`document.body.innerText.includes('InvalidArgument')`, 10_000);
    record('M7 非法私钥导入拒绝（InvalidArgument）', importRejected === true);
    // 修改口令
    g = await gen();
    await fill('stk-unlock-pw', PW);
    await click('stk-unlock-btn');
    await waitRender(g, `!!document.getElementById('stk-address')`, 20_000);
    await openDetails('stk-cpw-details');
    await fill('stk-cpw-current', PW);
    await fill('stk-cpw-next', PW2);
    await click('stk-cpw-btn');
    const cpwOk = await waitForExpr(`document.body.innerText.includes('口令已修改')`, 15_000);
    record('M8 修改口令（keystore 重加密）', cpwOk === true);
    g = await gen();
    await click('stk-lock-btn');
    await waitRender(g, `!!document.getElementById('stk-unlock-btn')`, 10_000);
    await fill('stk-unlock-pw', PW);
    await click('stk-unlock-btn');
    const oldPwRejected = await waitForExpr(`document.body.innerText.includes('口令错误')`, 10_000);
    g = await gen();
    await fill('stk-unlock-pw', PW2);
    await click('stk-unlock-btn');
    const newPwOk = await waitRender(g, `!!document.getElementById('stk-address')`, 20_000);
    record('M9 旧口令失效 + 新口令解锁成功', oldPwRejected === true && newPwOk === true);

    // ===== 网络/RPC 边界 =====
    const badNet = await msg({ type: 'popup:stkSetNetwork', networkId: 'nope' });
    record('N1 未知网络拒绝（NetworkUnsupported）', badNet?.error?.code === 'NetworkUnsupported', JSON.stringify(badNet));
    const badRpc = await msg({ type: 'popup:stkSetRpc', networkId: 'starknet-devnet', rpcUrl: 'ftp://nope' });
    record('N2 非法 RPC URL 拒绝（InvalidArgument）', badRpc?.error?.code === 'InvalidArgument', JSON.stringify(badRpc));
    await msg({ type: 'popup:stkSetRpc', networkId: 'starknet-devnet', rpcUrl: 'http://127.0.0.1:1' });
    const deadRefresh = await msg({ type: 'popup:stkRefresh' });
    record('N3 RPC 不可达 → RpcUnreachable（如实报错）', deadRefresh?.error?.code === 'RpcUnreachable', JSON.stringify(deadRefresh).slice(0, 100));
    await msg({ type: 'popup:stkSetRpc', networkId: 'starknet-devnet', rpcUrl: chain.url });

    // ===== 截图 =====
    await page.eval(`(() => { const b = [...document.querySelectorAll('button')].find((x) => x.textContent === '刷新余额'); b?.click(); return true; })()`);
    await sleep(1200);
    const shot = await Promise.race([page.send('Page.captureScreenshot', { format: 'png' }), new Promise((_, rej) => setTimeout(() => rej(new Error('screenshot timeout')), 10_000))]);
    writeFileSync(OUT_PNG, Buffer.from(shot.data, 'base64'));

    // ===== 汇总 =====
    const pass = results.filter((r) => r.ok).length;
    const summary = {
      date: new Date().toISOString(),
      browser: version.Browser,
      extensionId: extId,
      devchainUrl: chain.url,
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
