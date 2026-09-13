// =============================================================================
// extension/tests/networks.test.js — 网络注册表测试（Extension 0.2）
//
// 覆盖：注册表解析（devnet/testnet）/ mainnet 红线（不注册即拒）/
// 网关 URL 解析（默认值、用户覆盖、testnet 未配置如实 null）/ URL 规范化 /
// explorer 链接构造。
// =============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  DEFAULT_NETWORK_ID,
  MAINNET_CHAIN_ID,
  NETWORK_IDS,
  canonicalHttpUrl,
  checkSwitchTarget,
  effectiveGatewayUrl,
  resolveNetwork,
  settlementExplorerUrl,
} from '../common/networks.js';

test('01 注册表：devnet/testnet 已登记且字段齐全；默认 devnet', () => {
  assert.deepEqual(NETWORK_IDS.sort(), ['zchain-devnet-1', 'zchain-testnet-1']);
  for (const id of NETWORK_IDS) {
    const net = resolveNetwork(id);
    assert.ok(net, id);
    assert.equal(net.chainId, id);
    assert.equal(net.abiVersion, 1);
    assert.ok(['devnet', 'testnet'].includes(net.kind));
  }
  assert.equal(DEFAULT_NETWORK_ID, 'zchain-devnet-1');
  assert.equal(resolveNetwork('zchain-devnet-1').kind, 'devnet');
  assert.equal(resolveNetwork('zchain-testnet-1').kind, 'testnet');
});

test('02 mainnet 红线：注册表刻意不含 mainnet，解析为 null', () => {
  assert.equal(resolveNetwork(MAINNET_CHAIN_ID), null);
  assert.equal(resolveNetwork('zchain-mainnet-1'), null);
  assert.equal(resolveNetwork('ethereum'), null);
  assert.equal(resolveNetwork(''), null);
  assert.equal(resolveNetwork(null), null);
  assert.equal(resolveNetwork(undefined), null);
});

test('03 checkSwitchTarget：未登记网络（含 mainnet）→ NetworkUnsupported；已登记 → ok', () => {
  const mainnet = checkSwitchTarget('zchain-mainnet-1');
  assert.equal(mainnet.ok, false);
  assert.equal(mainnet.code, 'NetworkUnsupported');
  // 红线理由必须明示"刻意不配置"（不是"未上线"的含糊说法）。
  assert.match(mainnet.reason, /intentionally not configured/);

  const junk = checkSwitchTarget('0x1');
  assert.equal(junk.ok, false);
  assert.equal(junk.code, 'NetworkUnsupported');

  assert.equal(checkSwitchTarget('zchain-testnet-1').ok, true);
  assert.equal(checkSwitchTarget('zchain-devnet-1').ok, true);
});

test('04 网关 URL：devnet 有默认；用户覆盖优先；testnet 未配置如实 null', () => {
  // devnet 默认（本地 replay 网关）
  assert.equal(effectiveGatewayUrl('zchain-devnet-1', {}), 'http://127.0.0.1:18900');
  // 用户覆盖（规范化去路径/尾斜杠）
  assert.equal(
    effectiveGatewayUrl('zchain-devnet-1', { 'zchain-devnet-1': { gatewayUrl: 'http://localhost:9999/' } }),
    'http://localhost:9999',
  );
  // testnet：未部署公共网关 → null（不得回落 devnet）
  assert.equal(effectiveGatewayUrl('zchain-testnet-1', {}), null);
  // testnet 设置后可用
  assert.equal(
    effectiveGatewayUrl('zchain-testnet-1', { 'zchain-testnet-1': { gatewayUrl: 'https://gw.example.net' } }),
    'https://gw.example.net',
  );
  // 未知网络 → null
  assert.equal(effectiveGatewayUrl('zchain-mainnet-1', {}), null);
  // 非法覆盖（非 http(s)）→ 回落默认值（devnet）或 null（testnet）
  assert.equal(
    effectiveGatewayUrl('zchain-devnet-1', { 'zchain-devnet-1': { gatewayUrl: 'ftp://x' } }),
    'http://127.0.0.1:18900',
  );
});

test('05 canonicalHttpUrl：只接受 http(s) 源；去路径；非法 → null', () => {
  assert.equal(canonicalHttpUrl('http://127.0.0.1:18900/api/v1'), 'http://127.0.0.1:18900');
  assert.equal(canonicalHttpUrl('https://gw.example:8443'), 'https://gw.example:8443');
  assert.equal(canonicalHttpUrl('ftp://x'), null);
  assert.equal(canonicalHttpUrl('javascript:alert(1)'), null);
  assert.equal(canonicalHttpUrl('not a url'), null);
  assert.equal(canonicalHttpUrl(''), null);
  assert.equal(canonicalHttpUrl('x'.repeat(257)), null);
});

test('06 explorer 链接：按网络构造 settlement 链接；未配置 → null（不伪造）', () => {
  assert.equal(
    settlementExplorerUrl('zchain-devnet-1', {}, 'ab'.repeat(32)),
    'http://127.0.0.1:18900/api/v1/settlement/' + 'ab'.repeat(32),
  );
  assert.equal(settlementExplorerUrl('zchain-testnet-1', {}, 'ab'.repeat(32)), null);
  assert.equal(settlementExplorerUrl('zchain-testnet-1', { 'zchain-testnet-1': { explorerBase: 'https://ex.example' } }, 'ab'.repeat(32)), 'https://ex.example/api/v1/settlement/' + 'ab'.repeat(32));
  assert.equal(settlementExplorerUrl('zchain-mainnet-1', {}, 'ab'.repeat(32)), null);
});
