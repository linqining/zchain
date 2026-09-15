// =============================================================================
// extension/common/stark/invoke.js — invoke v1 交易组装与签名（Extension 0.6）
//
// 纯函数：calldata 组装（[to, selector, len, ...args]）、交易哈希
// （Pedersen 元素链）、签名 [r, s]、RPC invocation 形状。
// =============================================================================

import {
  calculateInvokeTransactionHash, ecSign, starknetSelector, toFelt,
  encodeShortString, hexToBigInt, bigIntToHex, u256ToFeltPair,
} from './curve.js';

/** 金额（人类可读十进制，按 decimals）→ u256 felt 对 [low, high] 的 hex。 */
export function amountToFelts(amountHuman, decimals) {
  const m = /^(\d+)(?:\.(\d+))?$/.exec(String(amountHuman).trim());
  if (!m) {
    const e = new Error('金额格式非法');
    e.code = 'InvalidArgument';
    throw e;
  }
  const frac = (m[2] ?? '').slice(0, decimals).padEnd(decimals, '0');
  const wei = BigInt(m[1]) * 10n ** BigInt(decimals) + (frac ? BigInt(frac) : 0n);
  const [lo, hi] = u256ToFeltPair(wei);
  return [bigIntToHex(lo), bigIntToHex(hi)];
}

/** u256 felt 对 → 人类可读十进制（带小数点，去尾零）。 */
export function feltsToAmount([loHex, hiHex], decimals) {
  const lo = hexToBigInt(loHex);
  const hi = hiHex != null ? hexToBigInt(hiHex) : 0n;
  const wei = lo | (hi << 128n);
  const base = 10n ** BigInt(decimals);
  const whole = wei / base;
  const frac = (wei % base).toString().padStart(decimals, '0').replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : whole.toString();
}

/**
 * 组装账户 invoke calldata（单调用）：[to, selector, calldata_len, ...args]。
 * @param {object} p {to, entryPointSelector|functionName, calldata: felt hex 数组}
 */
export function buildInvokeCalldata({ to, entryPointSelector, functionName, calldata = [] }) {
  const selector = entryPointSelector != null ? toFelt(entryPointSelector) : starknetSelector(functionName);
  const args = calldata.map((c) => bigIntToHex(toFelt(c)));
  return [bigIntToHex(toFelt(to)), bigIntToHex(selector), bigIntToHex(BigInt(args.length)), ...args];
}

/**
 * 构造并签名 invoke v1。
 * @param {object} p {senderAddress, to, functionName?, entryPointSelector?, calldata?,
 *                    nonce, maxFee, chainIdFelt, privateKey}
 * @returns {{invocation, txHash, signature: [rHex, sHex], calldata}}
 */
export function signInvoke({ senderAddress, to, functionName, entryPointSelector, calldata = [], nonce, maxFee, chainIdFelt, privateKey }) {
  const data = buildInvokeCalldata({ to, entryPointSelector, functionName, calldata });
  const txHash = calculateInvokeTransactionHash({
    version: 1n,
    senderAddress,
    calldata: data,
    maxFee: toFelt(maxFee),
    chainId: typeof chainIdFelt === 'bigint' ? chainIdFelt : hexToBigInt(chainIdFelt),
    nonce: toFelt(nonce),
  });
  const { r, s } = ecSign(txHash, typeof privateKey === 'bigint' ? privateKey : hexToBigInt(privateKey));
  return {
    txHash: bigIntToHex(txHash),
    signature: [bigIntToHex(r), bigIntToHex(s)],
    calldata: data,
    invocation: {
      type: 'INVOKE',
      version: '0x1',
      max_fee: bigIntToHex(toFelt(maxFee)),
      signature: [bigIntToHex(r), bigIntToHex(s)],
      nonce: bigIntToHex(toFelt(nonce)),
      sender_address: bigIntToHex(toFelt(senderAddress)),
      calldata: data,
    },
  };
}
