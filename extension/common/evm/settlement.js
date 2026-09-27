// =============================================================================
// extension/common/evm/settlement.js — 结算链（L1 host）钱包能力面
//
// 加链即用契约（docs/plan-multi-settlement-architecture.md §钱包）：
// 在 common/evm/networks.js 登记一个新条目并携带
//   { settlement: true, bridgeAddress: '0x…', inboxAddress: '0x…' }
// 则钱包的"登录"（网络视图/RPC/explorer，evmNetworkView 已覆盖）与
// "买入"（本模块 buildDepositIntent：原生币锁入 L1Bridge → L2 铸 note）
// **自动可用**，无需改任何其他代码。
//
// 纯函数、零副作用（node --test 直覆盖）。
// =============================================================================

import { isAddress } from './crypto.js';
import { parseAbi, buildWriteIntent } from './contracts.js';

/** L1Bridge 入金 ABI（与 contracts/monad/src/L1Bridge.sol 对齐；parseAbi 预处理）。 */
export const ZCHAIN_BRIDGE_ABI = [
  { type: 'function', name: 'depositNative', stateMutability: 'payable',
    inputs: [{ name: 'to', type: 'address' }], outputs: [] },
  { type: 'function', name: 'depositToken', stateMutability: 'nonpayable',
    inputs: [{ name: 'token', type: 'address' }, { name: 'to', type: 'address' }, { name: 'amount', type: 'uint256' }],
    outputs: [] },
  { type: 'event', name: 'DepositInitiated', anonymous: false,
    inputs: [
      { name: 'nonce', type: 'uint256', indexed: true },
      { name: 'token', type: 'address', indexed: true },
      { name: 'to', type: 'address', indexed: true },
      { name: 'amount', type: 'uint256', indexed: false },
    ] },
];

const BRIDGE_ABI = parseAbi(ZCHAIN_BRIDGE_ABI);

/** 该网络是否为 zchain 结算层（L2 承诺锚定目标）。 */
export function isSettlementChain(network) {
  return Boolean(network && network.settlement === true);
}

/**
 * 结算能力视图（popup 按 capability 决定展示/隐藏）：
 * - login：网络视图/RPC/explorer 已由 evmNetworkView 覆盖（登记即有）；
 * - buyIn：原生币买入 = depositNative，需 settlement + bridgeAddress；
 * - claim：提现领取面（经 monad-settlement daemon / outbox；登记即预留）。
 */
export function settlementCapabilities(network) {
  if (!isSettlementChain(network)) {
    return { settlement: false, login: false, buyIn: false, claim: false };
  }
  return {
    settlement: true,
    login: true,
    buyIn: isAddress(network.bridgeAddress ?? ''),
    claim: true,
  };
}

/**
 * 原生币买入意图：把 amount（最小单位字符串）锁入该链的 L1Bridge，
 * 指定 L2 收款人 recipient。返回值可直接交给 prepareTx（预览→确认→签名广播）。
 *
 * # Errors（typed）
 * - ChainNotSettlement：该网络不是结算链；
 * - BridgeNotConfigured：登记为结算链但 bridgeAddress 未配置；
 * - InvalidArgument：recipient 非法地址。
 */
export function buildDepositIntent(network, { recipient, amount }) {
  if (!isSettlementChain(network)) {
    const e = new Error('该网络不是 zchain 结算层，不支持买入');
    e.code = 'ChainNotSettlement';
    throw e;
  }
  if (!isAddress(network.bridgeAddress ?? '')) {
    const e = new Error('该结算链未配置 L1Bridge 地址（network.bridgeAddress）');
    e.code = 'BridgeNotConfigured';
    throw e;
  }
  if (!isAddress(recipient)) {
    const e = new Error('L2 收款人地址非法');
    e.code = 'InvalidArgument';
    throw e;
  }
  const amountWei = BigInt(amount);
  if (!(amountWei > 0n)) {
    const e = new Error('买入金额必须为正');
    e.code = 'InvalidAmount';
    throw e;
  }
  const depositNative = BRIDGE_ABI.byName.depositNative;
  const intent = buildWriteIntent(depositNative, [recipient], {
    contract: network.bridgeAddress,
    value: amountWei.toString(),
  });
  return { ...intent, methodLabel: 'depositNative(L1Bridge)', settlementChainId: network.chainIdHex };
}

/**
 * ERC-20 买入意图（USDT/USDC 等）：两步 —— 先 approve 再 depositToken。
 * 返回 { approve, deposit } 两个 write intent（按序提交）。
 *
 * # Errors
 * 同 buildDepositIntent；另 token 非法地址 → InvalidArgument。
 */
export function buildTokenDepositIntents(network, { token, recipient, amount }) {
  if (!isSettlementChain(network)) {
    const e = new Error('该网络不是 zchain 结算层，不支持买入');
    e.code = 'ChainNotSettlement';
    throw e;
  }
  if (!isAddress(network.bridgeAddress ?? '')) {
    const e = new Error('该结算链未配置 L1Bridge 地址（network.bridgeAddress）');
    e.code = 'BridgeNotConfigured';
    throw e;
  }
  if (!isAddress(token) || !isAddress(recipient)) {
    const e = new Error('token/recipient 地址非法');
    e.code = 'InvalidArgument';
    throw e;
  }
  const amountWei = BigInt(amount);
  if (!(amountWei > 0n)) {
    const e = new Error('买入金额必须为正');
    e.code = 'InvalidAmount';
    throw e;
  }
  const depositToken = BRIDGE_ABI.byName.depositToken;
  const approve = parseAbi([{ type: 'function', name: 'approve', stateMutability: 'nonpayable',
    inputs: [{ name: 'spender', type: 'address' }, { name: 'amount', type: 'uint256' }], outputs: [{ type: 'bool' }] }]).byName.approve;
  return {
    approve: buildWriteIntent(approve, [network.bridgeAddress, amountWei.toString()], { contract: token }),
    deposit: buildWriteIntent(depositToken, [token, recipient, amountWei.toString()], { contract: network.bridgeAddress }),
    settlementChainId: network.chainIdHex,
  };
}
