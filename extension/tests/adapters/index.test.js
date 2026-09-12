// =============================================================================
// extension/tests/adapters/index.test.js — 适配器注册面/开关测试
//
// 覆盖：默认配置（安全默认）· 配置合并（fail-closed 值域）· WC 无 SignClient
// 注入时如实 dormant · 关闭开关的真实效果（不创建/拒绝）· status 不虚报。
// =============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { DEFAULT_ADAPTER_CONFIG, initAdapters, resolveAdapterConfig } from '../../adapters/index.js';
import { createSignClientStub } from '../../adapters/wc_signclient_stub.js';

function fakeZchain() {
  return {
    getNetwork: async () => ({ chainId: 'zchain-devnet-1' }),
    getCapabilities: async () => ({ methods: ['zchain_getAccounts'] }),
    getAccounts: async () => ({ accounts: ['ab'.repeat(33)] }),
  };
}

test('01 默认配置是安全默认：全启用，但 WC 需注入 SignClient', () => {
  assert.deepEqual(DEFAULT_ADAPTER_CONFIG, {
    eip1193: { enabled: true },
    walletconnect: { enabled: true, requireInjectedSignClient: true, sessionTtlSec: 7 * 24 * 3600 },
    starknet: { enabled: true },
  });
  const host = initAdapters({ zchain: fakeZchain() });
  const st = host.status();
  assert.equal(st.eip1193.enabled, true);
  assert.equal(st.walletconnect.active, false); // 无 SignClient → dormant（如实）
  assert.ok(st.warnings.join(' ').includes('dormant'));
});

test('02 配置合并 fail-closed：非法值回落默认、未知开关无效果', () => {
  const cfg = resolveAdapterConfig({
    eip1193: { enabled: 'yes' }, // 非 boolean → 回落 true
    walletconnect: { enabled: false, requireInjectedSignClient: 'no', sessionTtlSec: -5 },
    starknet: { enabled: 0 },
  });
  assert.equal(cfg.eip1193.enabled, true);
  assert.equal(cfg.walletconnect.enabled, false);
  assert.equal(cfg.walletconnect.requireInjectedSignClient, true);
  assert.equal(cfg.walletconnect.sessionTtlSec, 7 * 24 * 3600);
  assert.equal(cfg.starknet.enabled, true); // 0 非 boolean → 默认 true
});

test('03 WC：注入 SignClient 后激活；未注入不挂事件（dormant 即无会话面）', async () => {
  // dormant：connect 没有任何 wallet 侧监听者 → stub 的 connect promise 永远挂起。
  const dormantHost = initAdapters({ zchain: fakeZchain() });
  assert.equal(dormantHost.walletconnect, null);
  // 激活：注入 stub。
  const signClient = createSignClientStub();
  const host = initAdapters({ zchain: fakeZchain(), signClient });
  assert.equal(host.walletconnect != null, true);
  const session = await signClient.connect({
    requiredNamespaces: { zchain: { chains: ['zchain:zchain-devnet-1'], methods: ['zchain_getAccounts'], events: [] } },
  });
  assert.equal(host.status().walletconnect.sessions, 1);
  assert.equal(session.topic != null, true);
  host.walletconnect.detach();
});

test('04 开关关闭的真实效果：eip1193 disabled → createEip1193 拒绝', () => {
  const host = initAdapters({ zchain: fakeZchain(), config: { eip1193: { enabled: false } } });
  const r = host.createEip1193();
  assert.equal(r.ok, false);
  assert.equal(r.code, 'AdapterDisabled');
  assert.equal(host.status().eip1193.enabled, false);
  // enabled 时返回可用的 provider。
  const host2 = initAdapters({ zchain: fakeZchain() });
  const r2 = host2.createEip1193();
  assert.equal(r2.ok, true);
  assert.equal(r2.provider.isZChainEip1193Shim, true);
  assert.equal(r2.provider.isMetaMask, undefined); // 绝不伪装
});
