#!/usr/bin/env node
// =============================================================================
// run_05.mjs — Extension 0.5 EVM 钱包：真实浏览器 E2E（浏览器操作）
//
// 驱动方式与 run_02/03/04 相同：Chrome for Testing + --headless=new +
// --load-extension（unpacked）+ CDP WebSocket；**所有用户路径都通过真实
// popup UI 操作**（点击/输入/确认），链侧用本 runner 启动的本地开发链
// （devchain.mjs：真实 RLP/EIP-155 解码与 sender 恢复）。
//
// 覆盖（对照交付要求）：
//   1. 钱包余额查询：水龙头领取 → 刷新余额 → 余额/nonce/gas/chainId 展示；
//   2. 合约调用：ERC-20 预设只读（symbol/balanceOf，金额换算）+ 合约写
//      （faucet 铸币 / transfer 转账）→ 交易预览确认 → 真实签名广播 →
//      链上状态核对；
//   3. 交易记录查询：本地账本 + 链上 explorer txlist 合并 → 状态/金额/
//      hash 列表；
//   4. 钱包管理：创建（口令加密 keystore）、锁定/解锁（错口令 fail-closed）、
//      私钥导出（口令确认）、导出私钥再导入同址、修改口令（旧口令失效）；
//   5. 本文件即 e2e（浏览器操作），结果落 JSON + 截图。
//
// 用法（repo 根目录）：node extension/tests/e2e/run_05.mjs
// 退出码：0 = 全部 PASS；1 = 存在 FAIL。
// =============================================================================

import { spawn } from 'node:child_process';
import { appendFileSync, existsSync, mkdtempSync, readdirSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startDevChain } from './devchain.mjs';
import { toChecksumAddress } from '../../common/evm/crypto.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const EXT_ROOT = path.resolve(HERE, '..', '..');
const OUT_JSON = path.join(HERE, 'e2e05_result.json');
const OUT_PNG = path.join(HERE, 'e2e05_screenshot.png');
const PROGRESS = path.join(HERE, 'e2e05_progress.log');

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
  const chain = await startDevChain({ port: 0 });
  progress(`devchain: ${chain.url} (contract ${chain.contract})`);

  const profileDir = mkdtempSync(path.join(tmpdir(), 'zchain_e2e05_'));
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
    const popup = await connectCdp(popupTarget, 'popup');
    const page = popup; // popup 页就是被测 UI
    const msg = (m) => page.eval(`chrome.runtime.sendMessage(${JSON.stringify(m)})`, 60_000);

    /** 轮询页面条件（真实 DOM 状态）。 */
    async function waitForExpr(expr, timeoutMs = 15_000, interval = 250) {
      const t0 = Date.now();
      for (;;) {
        let v = null;
        try { v = await page.eval(expr, 5_000); } catch { /* 页面重渲染瞬间 */ }
        if (v) return v;
        if (Date.now() - t0 > timeoutMs) return null;
        await sleep(interval);
      }
    }
    /** UI 操作助手：填输入 → 点按钮（真实浏览器操作）。 */
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
    const text = (selector) => page.eval(`document.getElementById(${JSON.stringify(selector)})?.textContent ?? null`).catch(() => null);
    const bodyHas = (needle) => page.eval(`document.body.innerText.includes(${JSON.stringify(needle)})`).catch(() => false);
    const openDetails = (selector) => page.eval(`(() => { const d = document.getElementById(${JSON.stringify(selector)}); if (!d) return false; d.open = true; return true; })()`).catch(() => false);
    /** 渲染代数：popup.js 每次 render() 完成后自增（window.__zRenderGen）。 */
    const gen = () => page.eval(`window.__zRenderGen ?? 0`).catch(() => 0);
    /** 等待"新一代渲染完成 + 效果成立"（避免操作落在旧 DOM 树上）。 */
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

    // ===== E0：扩展与模式切换 =====
    const hasEvmBtn = await waitForExpr(`!!document.getElementById('mode-evm')`);
    record('E0 popup 页加载 + 模式切换按钮存在', hasEvmBtn === true);
    // popup.js 是 module（deferred）：轮询点击直到视图切换生效（无固定 sleep 竞态）
    async function clickUntil(selector, effectExpr, timeoutMs = 20_000) {
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
    const evmCreateVisible = await clickUntil('mode-evm', `!!document.getElementById('evm-create-btn')`);
    record('E1 切换到 EVM 钱包 → 创建视图', evmCreateVisible === true);

    // ===== E2：创建钱包（口令加密 keystore）=====
    let g = await gen();
    await fill('evm-pw', PW);
    await fill('evm-pw2', PW);
    await click('evm-create-btn');
    await waitRender(g, `!!document.getElementById('evm-address')`, 30_000);
    const addrRaw = await waitForExpr(`document.getElementById('evm-address')?.textContent ?? null`, 10_000);
    const addrOk = typeof addrRaw === 'string' && /^0x[0-9a-fA-F]{40}$/.test(addrRaw)
      && toChecksumAddress(addrRaw) === addrRaw; // EIP-55 校验和
    record('E2 创建钱包（口令 → 加密 keystore）→ EIP-55 地址展示', addrOk, String(addrRaw));
    const state0 = await msg({ type: 'popup:evmGetState' });
    record('E2b SW 状态：hasWallet + unlocked + 账户列表',
      state0?.hasWallet === true && state0?.unlocked === true && state0.accounts?.length === 1
        && state0.networkId === 'evm-devnet',
      JSON.stringify({ hasWallet: state0?.hasWallet, unlocked: state0?.unlocked, n: state0?.accounts?.length }).slice(0, 100));

    // ===== E3：RPC 指向本地开发链 =====
    g = await gen();
    await fill('evm-rpc-input', chain.url);
    await click('evm-rpc-save');
    await waitRender(g, `!!document.getElementById('evm-faucet-amount')`, 15_000);
    const savedRpc = await msg({ type: 'popup:evmGetState' });
    const net = (savedRpc.networks ?? []).find((n) => n.id === 'evm-devnet');
    record('E3 保存 RPC 覆盖 → 生效 URL = devchain', net?.rpcUrl === chain.url && net?.rpcOverridden === true, String(net?.rpcUrl));

    // ===== ① 余额查询：水龙头 → 刷新 =====
    await fill('evm-faucet-amount', '100');
    await click('evm-faucet-btn');
    const balText = await waitForExpr(`(() => {
      const t = (document.getElementById('evm-balance')?.textContent ?? '').trim();
      return t === '100 ETH' ? t : null;
    })()`, 30_000, 300);
    record('F1 余额查询：水龙头 100 ETH → 余额展示', balText === '100 ETH', String(balText));
    const chainInfo = await waitForExpr(`(() => {
      const t = document.getElementById('evm-chain-info')?.textContent ?? '';
      return t.includes('0x7a69') && t.includes('gas') ? t : null;
    })()`, 10_000);
    record('F2 链状态行：chainId/nonce/gas 展示', !!chainInfo, String(chainInfo));
    const refresh = await msg({ type: 'popup:evmRefresh' });
    record('F3 SW 余额面：balanceWei=100e18 + nonce=0 + gasPrice',
      refresh?.balanceWei === (100n * 10n ** 18n).toString() && refresh?.nonce === '0'
        && BigInt(refresh?.gasPriceWei ?? 0) > 0n,
      JSON.stringify(refresh).slice(0, 140));

    // ===== ② 合约调用 =====
    const OTHER = toChecksumAddress('0x' + 'beef'.padEnd(40, '0'));
    // 只读：symbol()
    await fill('evm-contract', chain.contract);
    await fill('evm-method', 'symbol');
    await fill('evm-args', '');
    await click('evm-read-btn');
    const symText = await waitForExpr(`(document.getElementById('evm-read-result')?.innerText ?? '')`, 15_000);
    record('C1 合约只读（ERC-20 预设 symbol）→ DVT', String(symText).includes('DVT'), String(symText).replace(/\n/g, ' | ').slice(0, 120));
    // 写：faucet() 铸 1000 DVT 给自己（自定义 ABI 路径：演示合约的 faucet 不在
    // ERC-20 标准预设里，同时覆盖自定义 ABI 表单）
    await page.eval(`(() => {
      const sel = document.getElementById('evm-abi-preset');
      sel.value = 'custom';
      sel.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`);
    await fill('evm-abi-json', JSON.stringify([{ type: 'function', name: 'faucet', stateMutability: 'nonpayable', inputs: [], outputs: [] }]));
    await fill('evm-method', 'faucet');
    await fill('evm-args', '');
    await click('evm-write-btn');
    const previewShown = await waitForExpr(`!!document.getElementById('evm-tx-preview')`, 15_000);
    const previewText = previewShown ? await page.eval(`document.getElementById('evm-tx-preview').innerText`) : '';
    record('C2 合约写预览卡：faucet() + 最大手续费 + chainId',
      previewShown === true && String(previewText).includes('faucet()') && String(previewText).includes('最大手续费')
        && String(previewText).includes('0x7a69'),
      String(previewText).replace(/\n/g, ' | ').slice(0, 160));
    const gC1 = await gen();
    await click('evm-tx-confirm');
    const txHash1 = await waitForExpr(`window.__lastEvmBroadcast ?? null`, 30_000);
    await waitRender(gC1, `!!document.getElementById('evm-address')`, 15_000);
    record('C3 确认 → 签名广播（真实 raw 交易上链）', /^0x[0-9a-f]{64}$/.test(String(txHash1)), String(txHash1));
    const onchain1 = txHash1 ? chain.state.txs.get(String(txHash1).toLowerCase()) : null;
    record('C4 开发链核对：sender 恢复 = 钱包地址 + status 0x1',
      onchain1?.from?.toLowerCase() === String(state0.accounts?.[0]?.address).toLowerCase() && onchain1?.status === '0x1',
      JSON.stringify({ from: onchain1?.from, status: onchain1?.status }).slice(0, 120));
    // 只读：balanceOf（金额换算展示；切回 ERC-20 预设；render 会重置输入框 → 重新填合约地址）
    await page.eval(`(() => {
      const sel = document.getElementById('evm-abi-preset');
      sel.value = 'erc20';
      sel.dispatchEvent(new Event('change', { bubbles: true }));
      return true;
    })()`);
    await fill('evm-contract', chain.contract);
    await fill('evm-method', 'balanceOf');
    await fill('evm-args', state0.accounts[0].address);
    await click('evm-read-btn');
    const balOf = await waitForExpr(`(() => {
      const t = document.getElementById('evm-read-result')?.innerText ?? '';
      return t.includes('1000') ? t : null;
    })()`, 15_000);
    record('C5 合约只读 balanceOf → 1000（人类可读换算）',
      String(balOf).includes('1000'), String(balOf).replace(/\n/g, ' | ').slice(0, 140));
    // 写：transfer(other, 250)
    await fill('evm-method', 'transfer');
    await fill('evm-args', `${OTHER}, 250`);
    await click('evm-write-btn');
    await waitForExpr(`!!document.getElementById('evm-tx-confirm')`, 15_000);
    const gC2 = await gen();
    await click('evm-tx-confirm');
    const txHash2 = await waitForExpr(`window.__lastEvmBroadcast !== ${JSON.stringify(txHash1)} ? window.__lastEvmBroadcast : null`, 30_000);
    await waitRender(gC2, `!!document.getElementById('evm-address')`, 15_000);
    record('C6 合约写 transfer(OTHER,250) 广播', /^0x[0-9a-f]{64}$/.test(String(txHash2)), String(txHash2));
    await fill('evm-contract', chain.contract);
    await fill('evm-method', 'balanceOf');
    await fill('evm-args', OTHER);
    await click('evm-read-btn');
    const balOther = await waitForExpr(`(() => {
      const t = document.getElementById('evm-read-result')?.innerText ?? '';
      return t.includes('250') ? t : null;
    })()`, 15_000);
    record('C7 链上效果核对：balanceOf(OTHER) → 250',
      String(balOther).includes('250'), String(balOther).replace(/\n/g, ' | ').slice(0, 140));

    // ===== 原生转账 =====
    await fill('evm-tx-to', OTHER);
    await fill('evm-tx-value', '1.5');
    await click('evm-tx-prepare');
    await waitForExpr(`!!document.getElementById('evm-tx-confirm')`, 15_000);
    const gT1 = await gen();
    await click('evm-tx-confirm');
    const txHash3 = await waitForExpr(`window.__lastEvmBroadcast !== ${JSON.stringify(txHash2)} ? window.__lastEvmBroadcast : null`, 30_000);
    await waitRender(gT1, `!!document.getElementById('evm-address')`, 15_000);
    record('T1 原生转账 1.5 ETH → 广播', /^0x[0-9a-f]{64}$/.test(String(txHash3)), String(txHash3));
    // 拒绝路径：预览后取消（render 重置输入框 → 重新填地址）
    await fill('evm-tx-to', OTHER);
    await fill('evm-tx-value', '2');
    await click('evm-tx-prepare');
    await waitForExpr(`!!document.getElementById('evm-tx-reject')`, 15_000);
    await click('evm-tx-reject');
    const previewGone = await waitForExpr(`!document.getElementById('evm-tx-preview')`, 10_000);
    const notBroadcast = chain.state.txs.size === 3; // faucet + transfer + 原生 1.5
    record('T2 取消预览 → 不广播', previewGone === true && notBroadcast, `txs=${chain.state.txs.size}`);
    // 余额不足：150 ETH > 余额
    await fill('evm-tx-to', OTHER);
    await fill('evm-tx-value', '150');
    await click('evm-tx-prepare');
    const insufficient = await waitForExpr(`document.body.innerText.includes('InsufficientFunds')`, 15_000);
    record('T3 余额不足 → InsufficientFunds（预览前拒绝）', insufficient === true);
    await fill('evm-tx-to', OTHER);
    await fill('evm-tx-value', '0.5');
    await click('evm-tx-prepare');
    await waitForExpr(`!!document.getElementById('evm-tx-reject')`, 15_000);
    await click('evm-tx-reject');
    // 刷新余额：100 - 1.5 - gas(≈0.000000021)
    await click('evm-refresh-btn');
    const balAfter = await waitForExpr(`(() => {
      const t = (document.getElementById('evm-balance')?.textContent ?? '').trim();
      const v = parseFloat(t);
      return t !== '100 ETH' && v > 98.4 && v < 98.5 ? t : null;
    })()`, 20_000);
    record('T4 转账后余额刷新（≈98.5 − gas）', !!balAfter, String(balAfter));

    // ===== ③ 交易记录 =====
    // explorer API 指向 devchain 的 Etherscan 兼容端点（真实 UI 输入）
    g = await gen();
    await fill('evm-explorer-input', `${chain.url}/api`);
    await click('evm-explorer-save');
    await waitRender(g, `!!document.getElementById('evm-history-btn')`, 15_000);
    await click('evm-history-btn');
    const histOk = await waitForExpr(`(() => {
      const list = document.getElementById('evm-history-list');
      if (!list) return null;
      const boxes = list.querySelectorAll('.receipt').length;
      const confirmed = list.innerText.includes('已确认');
      return boxes >= 3 && confirmed ? boxes : null;
    })()`, 20_000);
    record('H1 交易记录列表：≥3 条本地记录 + 已确认状态', !!histOk, `boxes=${histOk}`);
    // explorer 合并（devchain 提供 Etherscan 兼容端点）
    await page.eval(`(() => { const cb = document.getElementById('evm-history-explorer'); cb.checked = true; return true; })()`);
    await click('evm-history-btn');
    const histExplorer = await waitForExpr(`(() => {
      const list = document.getElementById('evm-history-list');
      if (!list) return null;
      if (list.innerText.includes('未合并')) return 'note';
      return list.querySelectorAll('.receipt').length >= 3 ? 'merged' : null;
    })()`, 20_000);
    record('H2 explorer txlist 合并（Etherscan 兼容端点）', histExplorer === 'merged', String(histExplorer));
    const histDetail = await page.eval(`(() => {
      const list = document.getElementById('evm-history-list');
      const first = list.querySelector('.receipt');
      return first ? first.innerText : '';
    })()`);
    record('H3 记录明细：hash + 方向 + 金额 + 区块',
      /0x[0-9a-f]{20}/.test(String(histDetail)) && String(histDetail).includes('区块')
        && String(histDetail).includes('→'),
      String(histDetail).replace(/\n/g, ' | ').slice(0, 160));

    // ===== ④ 钱包管理 =====
    // 导出私钥：先错口令 fail-closed
    await openDetails('evm-export-details');
    await fill('evm-export-pw', 'wrong password!');
    await click('evm-export-btn');
    const exportDenied = await waitForExpr(`document.getElementById('evm-export-details')?.innerText.includes('口令错误')`, 10_000);
    record('M1 导出私钥：错口令 fail-closed（BadPassword）', exportDenied === true);
    await fill('evm-export-pw', PW);
    await click('evm-export-btn');
    const exportedKey = await waitForExpr(`document.getElementById('evm-exported-key')?.textContent ?? null`, 10_000);
    const exportOk = /^0x[0-9a-f]{64}$/.test(String(exportedKey));
    record('M2 导出私钥：口令确认 → 64 hex 私钥展示', exportOk, String(exportedKey).slice(0, 12) + '…');
    // 锁定 → 错口令 → 正确口令
    g = await gen();
    await click('evm-lock-btn');
    const unlockVisible = await waitRender(g, `!!document.getElementById('evm-unlock-btn') && !document.getElementById('evm-address')`, 10_000);
    await fill('evm-unlock-pw', 'totally wrong');
    await click('evm-unlock-btn');
    const unlockDenied = await waitForExpr(`document.body.innerText.includes('口令错误')`, 10_000);
    record('M3 锁定 → 错口令解锁拒绝（fail-closed）', unlockVisible === true && unlockDenied === true);
    g = await gen();
    await fill('evm-unlock-pw', PW);
    await click('evm-unlock-btn');
    const reUnlocked = await waitRender(g, `!!document.getElementById('evm-address')`, 20_000);
    record('M4 正确口令解锁恢复', reUnlocked === true);
    // SW 级守卫：锁定时准备交易 → SessionInvalid
    g = await gen();
    await click('evm-lock-btn');
    await waitRender(g, `!!document.getElementById('evm-unlock-btn')`, 10_000);
    const guard = await msg({ type: 'popup:evmPrepareTx', to: OTHER, valueEth: '1' });
    record('M5 锁定时 prepareTx → SessionInvalid（SW 守卫）', guard?.error?.code === 'SessionInvalid', JSON.stringify(guard));
    g = await gen();
    await fill('evm-unlock-pw', PW);
    await click('evm-unlock-btn');
    await waitRender(g, `!!document.getElementById('evm-address')`, 20_000);
    // 导出私钥再导入 → 同一地址（先删除当前账户：同私钥重复导入会被正确拒绝）
    await openDetails('evm-export-details');
    await fill('evm-export-pw', PW);
    await click('evm-export-btn');
    const key2Raw = await waitForExpr(`(() => {
      const k = document.getElementById('evm-exported-key')?.textContent;
      if (k) return { key: k };
      const t = document.getElementById('evm-export-details')?.innerText ?? '';
      if (t.includes('口令错误')) return { err: 'BadPassword' };
      return null;
    })()`, 10_000);
    const key2 = key2Raw?.key ?? null;
    // 私钥不入 result 工件：镜像 M2 的截断（前 12 hex + 省略号）。
    record('M6a 导出私钥（锁定/解锁循环后仍可用）', !!key2,
      JSON.stringify(key2Raw ? { key: String(key2Raw.key).slice(0, 12) + '…' } : null));
    await openDetails('evm-remove-details');
    g = await gen();
    await click('evm-remove-btn');
    const removed = await waitRender(g, `!!document.getElementById('evm-create-btn') && !!document.getElementById('evm-import-btn')`, 15_000);
    record('M6b 删除当前账户 → 回到创建视图', removed === true);
    await fill('evm-import-key', String(key2));
    await fill('evm-import-pw', PW);
    g = await gen();
    await click('evm-import-btn');
    const importRendered = await waitRender(g, `!!document.getElementById('evm-address')`, 30_000);
    const importedAddr = await waitForExpr(`document.getElementById('evm-address')?.textContent ?? null`, 10_000);
    record('M6 私钥再导入 → 同一 EIP-55 地址',
      importRendered === true && String(importedAddr).toLowerCase() === String(state0.accounts[0].address).toLowerCase()
        && toChecksumAddress(String(importedAddr)) === importedAddr,
      `${String(importedAddr).slice(0, 14)}… vs ${String(state0.accounts[0].address).slice(0, 14)}…`);
    // 坏私钥拒绝（锁定后导入卡可见）
    g = await gen();
    await click('evm-lock-btn');
    await waitRender(g, `!!document.getElementById('evm-import-btn')`, 10_000);
    await fill('evm-import-key', '0x1234');
    await fill('evm-import-pw', PW);
    await click('evm-import-btn');
    const importRejected = await waitForExpr(`document.body.innerText.includes('InvalidArgument')`, 10_000);
    record('M7 非法私钥导入拒绝（InvalidArgument）', importRejected === true);
    // 修改口令：新口令生效 + 旧口令失效
    g = await gen();
    await fill('evm-unlock-pw', PW);
    await click('evm-unlock-btn');
    await waitRender(g, `!!document.getElementById('evm-address')`, 20_000);
    await openDetails('evm-cpw-details');
    await fill('evm-cpw-current', PW);
    await fill('evm-cpw-next', PW2);
    await click('evm-cpw-btn');
    const cpwOk = await waitForExpr(`document.body.innerText.includes('口令已修改')`, 15_000);
    record('M8 修改口令（keystore 重加密）', cpwOk === true);
    g = await gen();
    await click('evm-lock-btn');
    await waitRender(g, `!!document.getElementById('evm-unlock-btn')`, 10_000);
    await fill('evm-unlock-pw', PW);
    await click('evm-unlock-btn');
    const oldPwRejected = await waitForExpr(`document.body.innerText.includes('口令错误')`, 10_000);
    g = await gen();
    await fill('evm-unlock-pw', PW2);
    await click('evm-unlock-btn');
    const newPwOk = await waitRender(g, `!!document.getElementById('evm-address')`, 20_000);
    record('M9 旧口令失效 + 新口令解锁成功', oldPwRejected === true && newPwOk === true);

    // ===== 网络/RPC 边界（SW 面）=====
    const badNet = await msg({ type: 'popup:evmSetNetwork', networkId: '0xdead' });
    record('N1 未知网络拒绝（NetworkUnsupported）', badNet?.error?.code === 'NetworkUnsupported', JSON.stringify(badNet));
    const badRpc = await msg({ type: 'popup:evmSetRpc', chainIdHex: '0x7a69', rpcUrl: 'ftp://nope' });
    record('N2 非法 RPC URL 拒绝（InvalidArgument）', badRpc?.error?.code === 'InvalidArgument', JSON.stringify(badRpc));
    const deadRpc = await msg({ type: 'popup:evmSetRpc', chainIdHex: '0x7a69', rpcUrl: 'http://127.0.0.1:1' });
    const deadRefresh = await msg({ type: 'popup:evmRefresh' });
    record('N3 RPC 不可达 → RpcUnreachable（如实报错）',
      deadRpc?.saved === true && deadRefresh?.error?.code === 'RpcUnreachable', JSON.stringify(deadRefresh).slice(0, 100));
    await msg({ type: 'popup:evmSetRpc', chainIdHex: '0x7a69', rpcUrl: '' }); // 恢复
    await msg({ type: 'popup:evmSetRpc', chainIdHex: '0x7a69', rpcUrl: chain.url });

    // ===== 截图（EVM 主面板最终态）=====
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
      contract: chain.contract,
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
