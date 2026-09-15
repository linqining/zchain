// =============================================================================
// extension/common/evm/contracts.js — 合约调用编码/解码（Extension 0.5）
//
// 最小 ABI 面（函数选择器 + 参数编解码）：uintN/intN/address/bool/
// bytes/bytesN/string + 一维数组。view/pure 走 eth_call（只读），其余
// 方法走交易路径。自带 ERC-20 预设 ABI（读 + 写），UI 免填 ABI 即可调用。
// =============================================================================

import { encodeTuple, decodeTuple, functionSelector, isAddress, parseUnits, formatUnits, hexToBytes } from './crypto.js';

/**
 * 解析 ABI JSON（数组形式）。返回函数表：
 * { byName: {name → fn}, bySelector: {0x… → fn} }
 * fn = { name, signature, selector, inputs:[{name,type}], outputTypes,
 *        view, stateMutability }
 */
export function parseAbi(abiJson) {
  const entries = typeof abiJson === 'string' ? JSON.parse(abiJson) : abiJson;
  if (!Array.isArray(entries)) {
    const e = new Error('ABI 必须是 JSON 数组');
    e.code = 'InvalidArgument';
    throw e;
  }
  const byName = {};
  const bySelector = {};
  for (const entry of entries) {
    if (entry?.type !== 'function') continue;
    const inputs = (entry.inputs ?? []).map((i) => ({ name: i.name ?? `arg${i.type}`, type: i.type }));
    const outputTypes = (entry.outputs ?? []).map((o) => o.type);
    const sig = `${entry.name}(${inputs.map((i) => i.type).join(',')})`;
    const mut = entry.stateMutability ?? (entry.constant === true ? 'view' : 'nonpayable');
    const fn = {
      name: entry.name,
      signature: sig,
      selector: functionSelector(sig),
      inputs,
      outputTypes,
      view: mut === 'view' || mut === 'pure' || entry.constant === true,
      payable: mut === 'payable',
      stateMutability: mut,
    };
    byName[fn.name] = fn;
    bySelector[fn.selector] = fn;
  }
  return { byName, bySelector };
}

/**
 * 编码合约调用 calldata。
 * @param {object} fn parseAbi 的函数条目
 * @param {Array} values 已按 UI 字符串给出的参数（内部做类型吸附）
 * @returns {string} 0x hex calldata
 */
export function encodeCall(fn, values = []) {
  if (!fn || !fn.signature) {
    const e = new Error('未知合约方法');
    e.code = 'UnknownMethod';
    throw e;
  }
  if (values.length !== fn.inputs.length) {
    const e = new Error(`参数数量不符：需要 ${fn.inputs.length} 个`);
    e.code = 'InvalidArgument';
    throw e;
  }
  const coerced = fn.inputs.map((input, i) => coerceArg(input.type, values[i]));
  const data = encodeTuple(fn.inputs.map((i) => i.type), coerced);
  return fn.selector + bytesToHexLower(data);
}

function bytesToHexLower(bytes) {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

/** UI 字符串 → ABI 值吸附（uint 用十进制字符串精确 BigInt；token 金额不在此换算）。 */
export function coerceArg(type, raw) {
  if (raw === undefined || raw === null || raw === '') {
    const e = new Error('参数缺失');
    e.code = 'InvalidArgument';
    throw e;
  }
  if (type === 'address') {
    if (!isAddress(String(raw))) {
      const e = new Error('参数地址非法');
      e.code = 'InvalidArgument';
      throw e;
    }
    return String(raw);
  }
  if (type === 'bool') return raw === true || raw === 'true' || raw === '1';
  if (/^uint|^int/.test(type)) return BigInt(String(raw).trim());
  if (type === 'string') return String(raw);
  return raw; // bytes/bytesN 保持 hex 字符串，encodeTuple 内部 hexToBytes
}

/**
 * 解码 eth_call 输出。
 * @returns {Array} 解码值数组（uint/int → 十进制字符串；address → EIP-55）
 */
export function decodeCallOutput(fn, resultHex) {
  const hex = String(resultHex ?? '0x');
  if (hex === '0x') return fn.outputTypes.map(() => null);
  return decodeTuple(fn.outputTypes, hex);
}

/** 解码值 → 展示字符串（uint 按可选 decimals 换算出人类可读金额）。 */
export function presentDecoded(fn, values, { decimalsByType = {} } = {}) {
  return fn.outputTypes.map((type, i) => {
    const v = values[i];
    const dec = decimalsByType[type];
    if (dec != null && /^uint/.test(type) && v != null) {
      return { type, raw: v, human: formatUnits(v, dec) };
    }
    return { type, raw: v, human: typeof v === 'boolean' ? String(v) : (v ?? '—') };
  });
}

// ---------------------------------------------------------------------------
// ERC-20 预设
// ---------------------------------------------------------------------------

export const ERC20_ABI = [
  { type: 'function', name: 'name', stateMutability: 'view', inputs: [], outputs: [{ type: 'string' }] },
  { type: 'function', name: 'symbol', stateMutability: 'view', inputs: [], outputs: [{ type: 'string' }] },
  { type: 'function', name: 'decimals', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint8' }] },
  { type: 'function', name: 'totalSupply', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'balanceOf', stateMutability: 'view',
    inputs: [{ name: 'account', type: 'address' }], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'transfer', stateMutability: 'nonpayable',
    inputs: [{ name: 'to', type: 'address' }, { name: 'amount', type: 'uint256' }], outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'approve', stateMutability: 'nonpayable',
    inputs: [{ name: 'spender', type: 'address' }, { name: 'amount', type: 'uint256' }], outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'allowance', stateMutability: 'view',
    inputs: [{ name: 'owner', type: 'address' }, { name: 'spender', type: 'address' }], outputs: [{ type: 'uint256' }] },
];

/** 常用预设（popup 下拉）。 */
export const ABI_PRESETS = {
  erc20: { label: 'ERC-20 代币', abi: ERC20_ABI },
};

/**
 * eth_call 只读调用（参数由 SW 组装；本函数只管编码 + 解码）。
 * callImpl: async ({to, data}) => hex
 */
export async function readContract({ contract, fn, args, callImpl }) {
  if (!isAddress(contract)) {
    const e = new Error('合约地址非法');
    e.code = 'InvalidArgument';
    throw e;
  }
  if (!fn.view) {
    const e = new Error(`${fn.name} 不是只读方法（view/pure），请走交易路径`);
    e.code = 'MethodNotView';
    throw e;
  }
  const data = encodeCall(fn, args);
  const raw = await callImpl({ to: contract, data });
  return { data, values: decodeCallOutput(fn, raw), raw };
}

/**
 * 写方法 → 交易意图（由 SW 走 prepareTx 流程：预览 → 确认 → 签名广播）。
 * tokenDecimals 存在时把金额参数从人类可读单位换算为 wei 粒度。
 */
export function buildWriteIntent(fn, args, { contract, value = '0', tokenDecimals = null } = {}) {
  if (!isAddress(contract)) {
    const e = new Error('合约地址非法');
    e.code = 'InvalidArgument';
    throw e;
  }
  if (fn.view) {
    const e = new Error(`${fn.name} 是只读方法，直接 eth_call 即可`);
    e.code = 'InvalidArgument';
    throw e;
  }
  const coerced = fn.inputs.map((input, i) => {
    let v = args[i];
    if (tokenDecimals != null && /^uint\d*$/.test(input.type) && input.type !== 'uint8') {
      v = parseUnits(v, tokenDecimals).toString(); // 人类可读金额 → 最小单位
    }
    return coerceArg(input.type, v);
  });
  return {
    to: contract,
    value,
    data: encodeCall(fn, coerced),
    methodLabel: fn.signature,
    decodedArgs: fn.inputs.map((input, i) => ({ name: input.name, type: input.type, value: String(coerced[i]) })),
  };
}
