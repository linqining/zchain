// =============================================================================
// extension/tests/capability_matrix.test.js — 外部钱包能力矩阵测试（Extension 0.4）
//
// 覆盖：EIP-1193/WC/Starknet 三协议行的 detected/active 状态、supported
// 列表（复用 adapters 白名单常量）、denied 列表与拒绝原因（红线文案），
// 探测 fail-closed（无注入对象 → 如实报未检测；WC 无 SignClient → dormant）。
// =============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { buildCapabilityMatrix, detectExternalWallets } from '../common/capability_matrix.js';
import { EIP1193_ETH_SIGNING_DENIED } from '../adapters/shared.js';

const ZCHAIN_CAPS = {
  provider: 'zchain',
  providerVersion: '0.4.0-alpha',
  networks: ['zchain-devnet-1', 'zchain-testnet-1'],
  currentNetwork: 'zchain-devnet-1',
  assetClasses: ['PLAY'],
  methods: ['zchain_requestAccounts', 'zchain_signOperation', 'zchain_getNotes'],
};

const ADAPTERS_DORMANT = {
  eip1193: { enabled: true, ethSubset: 'read-only (hard-coded)' },
  walletconnect: { enabled: true, active: false, sessions: 0 },
  starknet: { enabled: true },
  warnings: ['walletconnect dormant: no SignClient injected (production = @walletconnect/sign-client)'],
};

test('01 探测 fail-closed：干净全局对象 → 全部未检测；本钱包 provider 不误判', () => {
  const d = detectExternalWallets({ zchain: { isZChain: true, request: () => {} } });
  assert.equal(d.eip1193.detected, false);
  assert.equal(d.starknet.detected, false);
  // window.zchain 不是 EVM 钱包也不是 Starknet 钱包
  const d2 = detectExternalWallets({});
  assert.equal(d2.eip1193.detected, false);
});

test('02 探测：window.ethereum（含 providers 数组）与 starknet 形状', () => {
  const d = detectExternalWallets({
    ethereum: { isMetaMask: true, request: () => {} },
    starknet: {
      isConnected: true,
      account: { address: '0xabc' },
      signMessage: () => {},
      getChainId: () => {},
    },
  });
  assert.equal(d.eip1193.detected, true);
  assert.equal(d.eip1193.providers.length, 1);
  assert.equal(d.eip1193.providers[0].isMetaMask, true);
  assert.equal(d.starknet.detected, true);
  assert.equal(d.starknet.namespace, 'starknet');
  assert.equal(d.starknet.address, '0xabc');
  // providers 数组形状（多钱包共存）
  const d3 = detectExternalWallets({
    ethereum: { providers: [{ isMetaMask: true, request() {} }, { isRabby: true, request() {} }] },
  });
  assert.equal(d3.eip1193.providers.length, 2);
  assert.equal(d3.eip1193.providers[1].isRabby, true);
});

test('03 矩阵：EIP-1193 行 = 只读子集 supported + 签名全拒 denied（逐方法）', () => {
  const m = buildCapabilityMatrix({
    zchainCaps: ZCHAIN_CAPS,
    adapterStatus: ADAPTERS_DORMANT,
    detection: detectExternalWallets({ ethereum: { isMetaMask: true, request() {} } }),
  });
  assert.equal(m.own.currentNetwork, 'zchain-devnet-1');
  assert.equal(m.own.assetClasses.join(','), 'PLAY');
  const eip = m.rows.find((r) => r.protocol.startsWith('EIP-1193'));
  assert.equal(eip.detected, true);
  assert.equal(eip.active, true);
  const names = eip.supported.map((s) => s.name);
  for (const mth of ['eth_chainId', 'net_version', 'eth_accounts']) assert.ok(names.includes(mth), mth);
  assert.ok(names.includes('zchain_* 透传'));
  // 签名方法逐一出现在 denied 且带红线原因
  const denied = new Map(eip.denied.map((d) => [d.name, d.reason]));
  for (const mth of EIP1193_ETH_SIGNING_DENIED) {
    assert.ok(denied.has(mth), `missing denied: ${mth}`);
    assert.ok(denied.get(mth).includes('EvmSigningForbidden'));
  }
});

test('04 矩阵：WC dormant 如实展示（B5 外部依赖）；不虚报激活', () => {
  const m = buildCapabilityMatrix({
    zchainCaps: ZCHAIN_CAPS,
    adapterStatus: ADAPTERS_DORMANT,
    detection: {},
  });
  const wc = m.rows.find((r) => r.protocol === 'WalletConnect v2');
  assert.equal(wc.detected, true);
  assert.equal(wc.active, false);
  assert.equal(wc.supported.length, 0); // dormant = 无 supported 能力
  const reasons = wc.denied.map((d) => d.reason).join('\n');
  assert.ok(reasons.includes('dormant'));
  assert.ok(reasons.includes('B5'));
  assert.ok(wc.denied.some((d) => d.reason.includes('CapabilityMissing')));
});

test('05 矩阵：WC active（SignClient 已注入）→ supported = zchain 白名单', () => {
  const m = buildCapabilityMatrix({
    zchainCaps: ZCHAIN_CAPS,
    adapterStatus: { ...ADAPTERS_DORMANT, walletconnect: { enabled: true, active: true, sessions: 2 } },
    detection: {},
  });
  const wc = m.rows.find((r) => r.protocol === 'WalletConnect v2');
  assert.equal(wc.active, true);
  assert.ok(wc.summary.includes('2'));
  assert.ok(wc.supported.some((s) => s.name === 'zchain_signOperation'));
  // 盲签红线恒在
  assert.ok(wc.denied.some((d) => d.name.includes('盲签')));
});

test('06 矩阵：Starknet 行 = SNIP-12 授权委托 supported + note spend 拒绝', () => {
  const detected = buildCapabilityMatrix({
    zchainCaps: ZCHAIN_CAPS,
    adapterStatus: ADAPTERS_DORMANT,
    detection: { eip1193: { detected: false, providers: [] }, starknet: { detected: true, namespace: 'starknet', address: '0xabc' } },
  }).rows.find((r) => r.protocol.startsWith('Starknet'));
  assert.equal(detected.detected, true);
  assert.ok(detected.supported.some((s) => s.name.includes('AuthorizeZChainKey')));
  assert.ok(detected.denied.some((d) => d.name.includes('note spend') && d.reason.includes('ScopeForbidden')));
  assert.equal(detected.denied.filter((d) => d.name.includes('授权委托')).length, 0);

  // 未检测 → 授权委托如实标注不可用
  const absent = buildCapabilityMatrix({
    zchainCaps: ZCHAIN_CAPS,
    adapterStatus: ADAPTERS_DORMANT,
    detection: { eip1193: { detected: false, providers: [] }, starknet: { detected: false } },
  }).rows.find((r) => r.protocol.startsWith('Starknet'));
  assert.equal(absent.detected, false);
  assert.ok(absent.denied.some((d) => d.name.includes('授权委托') && d.reason.includes('未检测到')));
});
