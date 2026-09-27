// =============================================================================
// tests/evm/monad.test.js — Monad 结算层网络面（Extension × Monad L2 改造）
//
// 覆盖：
// 1. EVM 注册表：Monad 主网（143 / 0x8f）与测试网（10143 / 0x279f）的
//    官方参数（docs.monad.xyz）解析、RPC/explorer、settlement 标记；
// 2. zchain 网络注册表：devnet/testnet 携带 settlementL1 / settlementChainIdHex
//    结算层元数据（zchain L2 → Monad L1）。
// =============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  EVM_NETWORKS, resolveEvmNetwork, evmNetworkView,
} from '../../common/evm/networks.js';
import { NETWORKS, NETWORK_IDS, resolveNetwork } from '../../common/networks.js';

// ---------------------------------------------------------------------------
// EVM 注册表：Monad 主网 / 测试网
// ---------------------------------------------------------------------------

test('monad mainnet registered with official params', () => {
  const monad = resolveEvmNetwork('0x8f');
  assert.ok(monad, 'monad must resolve by chainIdHex');
  assert.equal(monad.chainIdHex, '0x8f');
  assert.equal(parseInt(monad.chainIdHex, 16), 143, 'mainnet chainId = 143');
  assert.equal(monad.id, 'monad');
  assert.equal(monad.rpcUrl, 'https://rpc.monad.xyz');
  assert.equal(monad.explorerUrl, 'https://monadvision.com');
  assert.equal(monad.kind, 'mainnet');
});

test('monad testnet registered with official params', () => {
  const t = resolveEvmNetwork('monad-testnet');
  assert.ok(t);
  assert.equal(parseInt(t.chainIdHex, 16), 10143, 'testnet chainId = 10143');
  assert.equal(t.rpcUrl, 'https://testnet-rpc.monad.xyz');
  assert.equal(t.kind, 'testnet');
});

test('settlement flag present only on monad entries', () => {
  const withSettlement = EVM_NETWORKS.filter((n) => n.settlement === true);
  assert.deepEqual(
    withSettlement.map((n) => n.id).sort(),
    ['monad', 'monad-testnet'],
  );
  // 非结算层网络在 view 中如实暴露 false（不缺字段）。
  const eth = evmNetworkView(resolveEvmNetwork('ethereum'), {}, {});
  assert.equal(eth.settlement, false);
  const monad = evmNetworkView(resolveEvmNetwork('monad'), {}, {});
  assert.equal(monad.settlement, true);
});

test('monad rpc override still wins over preset', () => {
  const overrides = { '0x8f': 'https://my-node.example:8545' };
  const view = evmNetworkView(resolveEvmNetwork('monad'), overrides, {});
  assert.equal(view.rpcUrl, 'https://my-node.example:8545');
  assert.equal(view.rpcOverridden, true);
});

// ---------------------------------------------------------------------------
// zchain 注册表：结算层元数据
// ---------------------------------------------------------------------------

test('zchain networks carry settlement layer metadata', () => {
  for (const id of NETWORK_IDS) {
    const net = resolveNetwork(id);
    assert.ok(net, `${id} resolves`);
    assert.match(net.settlementL1, /^monad/, `${id} settles to a Monad L1`);
    assert.match(net.settlementChainIdHex, /^0x[0-9a-f]+$/);
  }
  // devnet → 本地模拟；testnet → Monad 测试网（10143）。
  assert.equal(NETWORKS['zchain-devnet-1'].settlementL1, 'monad-devnet');
  assert.equal(NETWORKS['zchain-testnet-1'].settlementChainIdHex, '0x279f');
});

test('settlement chainIdHex agrees with evm registry entry', () => {
  for (const id of NETWORK_IDS) {
    const zchain = resolveNetwork(id);
    const l1 = resolveEvmNetwork(zchain.settlementChainIdHex);
    // devnet 的模拟结算层不在 EVM 注册表（本地 anvil），testnet 必须对上。
    if (zchain.kind === 'testnet') {
      assert.ok(l1, `settlement ${zchain.settlementChainIdHex} resolvable in evm registry`);
      assert.equal(l1.chainIdHex, zchain.settlementChainIdHex);
    }
  }
});
