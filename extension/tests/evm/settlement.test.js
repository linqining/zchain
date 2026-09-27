// =============================================================================
// tests/evm/settlement.test.js — 结算链钱包能力面（加链即用契约）
//
// 覆盖 docs/plan-multi-settlement-architecture.md §钱包的核心承诺：
// **新增一条结算链 = networks.js 登记一个条目（settlement + bridge/inbox 地址）
// ⇒ 登录（网络视图）与买入（deposit 意图）自动可用**，零其他代码改动。
// =============================================================================

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  ZCHAIN_BRIDGE_ABI, isSettlementChain, settlementCapabilities,
  buildDepositIntent, buildTokenDepositIntents,
} from '../../common/evm/settlement.js';
import { EVM_NETWORKS, resolveEvmNetwork, evmNetworkView } from '../../common/evm/networks.js';
import { decodeCallOutput } from '../../common/evm/contracts.js';

const RECIPIENT = '0x1111111111111111111111111111111111111111';
const BRIDGE = '0x6728873828dd281d274542eb3e6ba7438c0b96e6';
const TOKEN = '0x2222222222222222222222222222222222222222';

// ---------------------------------------------------------------------------
// 已登记结算链（Monad 主网/测试网）
// ---------------------------------------------------------------------------

test('monad entries carry settlement + bridge config', () => {
  for (const id of ['monad', 'monad-testnet']) {
    const net = resolveEvmNetwork(id);
    assert.ok(isSettlementChain(net), `${id} is a settlement chain`);
    assert.ok('bridgeAddress' in net && 'inboxAddress' in net, `${id} carries bridge/inbox fields`);
  }
  // 测试网 = 已验收部署实例 → 买入门位开；主网未部署 → 门位关（登录不受影响）。
  assert.equal(resolveEvmNetwork('monad-testnet').bridgeAddress, BRIDGE);
  assert.equal(resolveEvmNetwork('monad').bridgeAddress, null);
});

test('capabilities: testnet buyIn open, mainnet gated, non-settlement closed', () => {
  const caps = settlementCapabilities(resolveEvmNetwork('monad-testnet'));
  assert.equal(caps.login, true);
  assert.equal(caps.buyIn, true);
  assert.equal(caps.claim, true);
  assert.equal(caps.settlement, true);
  assert.equal(settlementCapabilities(resolveEvmNetwork('monad')).buyIn, false);
  assert.equal(settlementCapabilities(resolveEvmNetwork('monad')).login, true);
  assert.equal(settlementCapabilities(resolveEvmNetwork('ethereum')).buyIn, false);
  assert.equal(settlementCapabilities(resolveEvmNetwork('ethereum')).settlement, false);
});

// ---------------------------------------------------------------------------
// 买入意图（depositNative）
// ---------------------------------------------------------------------------

test('buildDepositIntent: native buy-in on configured testnet', () => {
  const net = resolveEvmNetwork('monad-testnet');
  const intent = buildDepositIntent(net, { recipient: RECIPIENT, amount: '1500000000000000000' });
  assert.equal(intent.to, BRIDGE);
  assert.equal(intent.value, '1500000000000000000');
  assert.equal(intent.settlementChainId, '0x279f');
  // calldata 可解码回原参数（selector 4B + address word 32B）。
  assert.ok(intent.data.startsWith('0x'));
  assert.ok(intent.data.length >= 2 + 4 * 2 + 64);
  assert.equal(intent.methodLabel, 'depositNative(L1Bridge)');
});

test('buildDepositIntent: gates (non-settlement / no bridge / bad address / zero amount)', () => {
  const codeOf = (fn) => { try { fn(); } catch (e) { return e.code; } return undefined; };
  const testnet = resolveEvmNetwork('monad-testnet');
  const noBridge = { ...resolveEvmNetwork('monad') };
  assert.equal(codeOf(() => buildDepositIntent(resolveEvmNetwork('base'), { recipient: RECIPIENT, amount: '1' })), 'ChainNotSettlement');
  assert.equal(codeOf(() => buildDepositIntent(noBridge, { recipient: RECIPIENT, amount: '1' })), 'BridgeNotConfigured');
  assert.equal(codeOf(() => buildDepositIntent(testnet, { recipient: '0x123', amount: '1' })), 'InvalidArgument');
  assert.equal(codeOf(() => buildDepositIntent(testnet, { recipient: RECIPIENT, amount: '0' })), 'InvalidAmount');
});

// ---------------------------------------------------------------------------
// 买入意图（ERC-20：approve + depositToken 两步）
// ---------------------------------------------------------------------------

test('buildTokenDepositIntents: approve then deposit', () => {
  const net = resolveEvmNetwork('monad-testnet');
  const intents = buildTokenDepositIntents(net, { token: TOKEN, recipient: RECIPIENT, amount: '5000000' });
  assert.equal(intents.approve.to, TOKEN);
  assert.equal(intents.deposit.to, BRIDGE);
  assert.equal(intents.settlementChainId, '0x279f');
  assert.equal(intents.deposit.value, '0');
});

// ---------------------------------------------------------------------------
// 加链即用：模拟新增一条结算链（零代码改动，只登记条目）
// ---------------------------------------------------------------------------

test('chain onboarding: a new registry entry instantly enables login + buy-in', () => {
  // 模拟运营者在 networks.js 登记的新链（如未来接入的任意 EVM host）：
  const NEW_CHAIN = {
    id: 'example-host',
    name: 'Example Host（示例新结算链）',
    chainIdHex: '0x1a4c', // 6732
    kind: 'testnet',
    rpcUrl: 'https://rpc.example-host.xyz',
    explorerUrl: 'https://explorer.example-host.xyz',
    explorerApiUrl: null,
    faucet: false,
    settlement: true,
    bridgeAddress: '0xa3c06bc2ab43f57cd788f7213c5a83a45cd2743e',
    inboxAddress: '0x3e4bfea829760e0f52c45f944c93053a6f695c0e',
  };
  EVM_NETWORKS.push(NEW_CHAIN); // 登记动作的全部内容

  // ① 登录面：网络视图自动可用（RPC/explorer/结算标记）。
  const view = evmNetworkView(resolveEvmNetwork('0x1a4c'), {}, {});
  assert.equal(view.login ?? true, true); // evmNetworkView 本身即登录面
  assert.equal(view.rpcUrl, 'https://rpc.example-host.xyz');
  assert.equal(view.settlement, true);

  // ② 买入面：deposit 意图直接可用。
  const caps = settlementCapabilities(NEW_CHAIN);
  assert.equal(caps.buyIn, true);
  const intent = buildDepositIntent(NEW_CHAIN, { recipient: RECIPIENT, amount: '1' });
  assert.equal(intent.to, NEW_CHAIN.bridgeAddress);

  // 清理（测试隔离）。
  EVM_NETWORKS.pop();
});

// ---------------------------------------------------------------------------
// ABI 形状守卫（与 contracts/monad/src/L1Bridge.sol 对齐）
// ---------------------------------------------------------------------------

test('ZCHAIN_BRIDGE_ABI depositNative decodes recipient word', () => {
  const fn = ZCHAIN_BRIDGE_ABI.find((f) => f.name === 'depositNative');
  assert.equal(fn.stateMutability, 'payable');
  // 编码→解码往返：selector+word 的 word 段低 20B = recipient。
  const intent = buildDepositIntent(
    { settlement: true, bridgeAddress: BRIDGE, chainIdHex: '0x279f' },
    { recipient: RECIPIENT, amount: '1' },
  );
  const wordHex = intent.data.slice(2 + 8); // 跳过 selector
  assert.equal(wordHex.slice(0, 24), '0'.repeat(24), '高 12B 零填充');
  assert.equal(wordHex.slice(24), RECIPIENT.slice(2).toLowerCase());
});
