// =============================================================================
// extension/common/stark/curve.js — STARK curve 密码学（Extension 0.6）
//
// Starknet 账户层的密码学边界（与 ZChain 路径的 wallet-core WASM、EVM 层的
// secp256k1 均互不影响）：
//   - STARK curve（StarkWare 曲线）：y² = x³ + x + β（mod p），
//     p = 2^251 + 17·2^192 + 1，阶 n，生成元 G，shift point；
//   - Pedersen hash（Starkware 版：shift point 起步 + 4-bit 常量点查表累加，
//     常量表逐字提取自 lambdaworks-crypto（与 StarkWare 同一张表））；
//   - computeHashOnElements（Pedersen 链，Starknet 元素哈希）；
//   - starknet_keccak（keccak256 结果 mod 2^250）与合约选择器；
//   - STARK curve ECDSA：sign（确定性 k：HMAC-keccak256 DRBG，RFC 6979
//     结构）/ verify（公钥只需 x 坐标）/ recover；
//   - Starknet 账户地址推导（CONTRACT_ADDRESS_PREFIX + UDC 公式，
//     mod 2^251 − 256）；短字符串 felt 编解码；u256 felt 对编解码。
//
// 正确性锚点（tests/stark/curve.test.js，全部公共向量）：
//   - 公钥推导：StarkWare crypto-cpp 官方向量（priv 0x12、priv 0x03c1…3cc、
//     keys_precomputed.json 样本）
//   - ECDSA 验证：crypto-cpp 官方正/负例
//   - Pedersen：StarkEx signature_test_data 官方向量 ×2
//   - 元素哈希/交易哈希：starknet.js 官方向量（SN_SEPOLIA 6 元素例）
//   - 地址推导：starknet.js calculateContractAddressFromHash 官方算例
//   - 选择器：'__validate__'（starknet.js 官方）、'transfer'（行业通用常量）
//   - 校验和地址：starknet.js 官方向量
// =============================================================================

import { keccak256, utf8ToBytes, hexToBytes, bytesToHex, bytesToBigInt } from '../evm/crypto.js';
import { SHIFT_POINT, POINTS_P1, POINTS_P2, POINTS_P3, POINTS_P4 } from './pedersen_points.js';

// ---------------------------------------------------------------------------
// 域与曲线常量
// ---------------------------------------------------------------------------

/** 域素数 p = 2^251 + 17·2^192 + 1。 */
export const FIELD_P = 0x800000000000011000000000000000000000000000000000000000000000001n;
/** 曲线阶 n。 */
export const EC_ORDER_N = 0x800000000000010ffffffffffffffffb781126dcae7b2321e66a241adc64d2fn;
/** beta（b），alpha（a）= 1。 */
export const CURVE_BETA = 0x6f21413efbe40de150e596d72f7a8c5609ad26c15c915c1f4cdfcb99cee9e89n;
const CURVE_ALPHA = 1n;
/** 生成元 G。 */
export const GENERATOR = {
  x: 0x1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfcan,
  y: 0x5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1fn,
};
/** 2^251 − 256：地址边界（ADDR_BOUND）。 */
export const ADDR_BOUND = 2n ** 251n - 256n;
/** felt 值域上界 2^251。 */
export const FELT_BOUND = 2n ** 251n;

export function modP(a) {
  const r = a % FIELD_P;
  return r >= 0n ? r : r + FIELD_P;
}

function modN(a) {
  const r = a % EC_ORDER_N;
  return r >= 0n ? r : r + EC_ORDER_N;
}

export function modInverse(a, m) {
  let [old_r, r] = [((a % m) + m) % m, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new Error('modInverse: not invertible');
  return ((old_s % m) + m) % m;
}

function modPow(base, exp, m) {
  let result = 1n;
  let b = ((base % m) + m) % m;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return result;
}

/** Tonelli–Shanks 模平方根（p ≡ 1 (mod 4)；p−1 = 2^192·(2^59+17)）。 */
export function modSqrt(a) {
  const y2 = modP(a);
  if (y2 === 0n) return 0n;
  if (modPow(y2, (FIELD_P - 1n) / 2n, FIELD_P) !== 1n) return null; // 非二次剩余
  // p - 1 = 2^e · q，e = 192，q = 2^59 + 17
  const e = 192n;
  const q = (FIELD_P - 1n) / 2n ** e;
  let z = 2n;
  while (modPow(z, (FIELD_P - 1n) / 2n, FIELD_P) !== FIELD_P - 1n) z += 1n; // 任一非二次剩余
  let m = e;
  let c = modPow(z, q, FIELD_P);
  let t = modPow(y2, q, FIELD_P);
  let r = modPow(y2, (q + 1n) / 2n, FIELD_P);
  while (t !== 1n) {
    let i = 0n;
    let t2 = t;
    while (t2 !== 1n) {
      t2 = (t2 * t2) % FIELD_P;
      i += 1n;
    }
    const b2 = modPow(c, 1n << (m - i - 1n), FIELD_P);
    m = i;
    c = (b2 * b2) % FIELD_P;
    t = (t * c) % FIELD_P;
    r = (r * b2) % FIELD_P;
  }
  return r;
}

// ---------------------------------------------------------------------------
// STARK 曲线点运算（Jacobian 坐标，a = 1）
// ---------------------------------------------------------------------------

const INF = [0n, 1n, 0n];

function jacDouble([x, y, z]) {
  if (y === 0n || z === 0n) return INF;
  const ysq = modP(y * y);
  const s = modP(4n * x * ysq);
  const m = modP(3n * x * x + z * z * z * z); // a = 1
  const x3 = modP(m * m - 2n * s);
  const y3 = modP(m * (s - x3) - 8n * ysq * ysq);
  const z3 = modP(2n * y * z);
  return [x3, y3, z3];
}

function jacAdd(p1, p2) {
  const [x1, y1, z1] = p1;
  const [x2, y2, z2] = p2;
  if (z1 === 0n) return p2;
  if (z2 === 0n) return p1;
  const z1z1 = modP(z1 * z1);
  const z2z2 = modP(z2 * z2);
  const u1 = modP(x1 * z2z2);
  const u2 = modP(x2 * z1z1);
  const s1 = modP(y1 * z2 * z2z2);
  const s2 = modP(y2 * z1 * z1z1);
  if (u1 === u2) {
    if (s1 !== s2) return INF;
    return jacDouble(p1);
  }
  const h = modP(u2 - u1);
  const r = modP(s2 - s1);
  const hh = modP(h * h);
  const hhh = modP(h * hh);
  const u1hh = modP(u1 * hh);
  const x3 = modP(r * r - hhh - 2n * u1hh);
  const y3 = modP(r * (u1hh - x3) - s1 * hhh);
  const z3 = modP(z1 * z2 * h);
  return [x3, y3, z3];
}

function jacMul(k, point) {
  let n = modN(k);
  if (n === 0n) return INF;
  let acc = INF;
  let addend = point;
  while (n > 0n) {
    if (n & 1n) acc = jacAdd(acc, addend);
    addend = jacDouble(addend);
    n >>= 1n;
  }
  return acc;
}

function jacToAffine([x, y, z]) {
  if (z === 0n) return null;
  const zinv = modInverse(z, FIELD_P);
  const zinv2 = modP(zinv * zinv);
  return [modP(x * zinv2), modP(y * zinv2 * zinv)];
}

/** 私钥（BigInt 或 hex 字符串）→ 公钥 x 坐标（Starknet 惯例：仅 x）。 */
export function privateKeyToPublicKey(priv) {
  const d = typeof priv === 'string' ? hexToBigInt(priv) : priv;
  if (d <= 0n || d >= EC_ORDER_N) throw new Error('stark: private key out of range');
  const [x] = jacToAffine(jacMul(d, [GENERATOR.x, GENERATOR.y, 1n]));
  return x;
}

/** 由公钥 x 坐标解出曲线上一点（±y 任一，ECDSA 验证只用 x）。 */
function decompressX(x) {
  if (x <= 0n || x >= FIELD_P) return null;
  const ysq = modP(x * x * x + CURVE_ALPHA * x + CURVE_BETA);
  const y = modSqrt(ysq);
  if (y === null || modP(y * y) !== ysq) return null;
  return [x, y, 1n];
}

/** 曲线上点断言（调试/测试用）。 */
export function isOnCurve(x, y) {
  return modP(y * y) === modP(x * x * x + CURVE_ALPHA * x + CURVE_BETA);
}

/** 内部点运算（仅供测试与 dev 链复用；勿在业务代码直接使用）。 */
export const _internals = { jacAdd, jacDouble, jacMul, jacToAffine, decompressX };

// ---------------------------------------------------------------------------
// hex / felt 工具
// ---------------------------------------------------------------------------

export function hexToBigInt(hex) {
  const h = String(hex).toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]*$/.test(h) || h.length === 0) throw new Error('stark: bad hex');
  return BigInt('0x' + h);
}

export function bigIntToHex(v) {
  return '0x' + BigInt(v).toString(16);
}

/** felt 合法性：0 ≤ v < 2^251。 */
export function isFelt(v) {
  try {
    const b = typeof v === 'bigint' ? v : hexToBigInt(v);
    return b >= 0n && b < FELT_BOUND;
  } catch {
    return false;
  }
}

export function toFelt(v) {
  const b = typeof v === 'bigint' ? v : hexToBigInt(v);
  if (b < 0n || b >= FELT_BOUND) throw new Error('stark: value out of felt range');
  return b;
}

/** 短字符串（≤ 31 字节 ASCII）→ felt。 */
export function encodeShortString(str) {
  const bytes = utf8ToBytes(String(str));
  if (bytes.length > 31) throw new Error('stark: short string too long');
  return bytesToBigInt(bytes);
}

/** felt → ASCII（可打印则返回字符串，否则 hex）。 */
export function decodeShortString(felt) {
  const v = typeof felt === 'bigint' ? felt : hexToBigInt(felt);
  const bytes = [];
  let x = v;
  while (x > 0n) {
    bytes.unshift(Number(x & 0xffn));
    x >>= 8n;
  }
  if (bytes.every((b) => b >= 0x20 && b <= 0x7e)) return String.fromCharCode(...bytes);
  return bigIntToHex(v);
}

/** u256 ⇄ felt 对（[low, high]，Starknet ERC-20 金额惯例）。 */
export function u256ToFeltPair(value) {
  const v = BigInt(String(value).trim());
  if (v < 0n || v >= 2n ** 256n) throw new Error('stark: u256 overflow');
  return [v & 0xffffffffffffffffffffffffffffffffn, v >> 128n];
}

export function feltPairToU256(low, high) {
  return toFelt(low) | (toFelt(high) << 128n);
}

// ---------------------------------------------------------------------------
// starknet_keccak 与选择器
// ---------------------------------------------------------------------------

/** starknet_keccak：keccak256 取 mod 2^250。 */
export function starknetKeccak(data) {
  const h = bytesToBigInt(keccak256(data));
  return h & (2n ** 250n - 1n);
}

/** 合约选择器：starknet_keccak(ascii 函数名)。 */
export function starknetSelector(name) {
  return starknetKeccak(utf8ToBytes(String(name)));
}

// ---------------------------------------------------------------------------
// Pedersen hash（Starkware 版）
// ---------------------------------------------------------------------------

const POINTS = [POINTS_P1, POINTS_P2, POINTS_P3, POINTS_P4];

function feltToBitsLE(v, len) {
  const bits = new Array(len).fill(false);
  for (let i = 0; i < len; i++) {
    bits[i] = ((v >> BigInt(i)) & 1n) === 1n;
  }
  return bits;
}

/** Pedersen 常量点（惰性解析为 BigInt 对，避免模块加载即全量转换）。 */
const POINTS_CACHE = POINTS.map((table) => null);
function pointAt(tableIdx, idx) {
  if (!POINTS_CACHE[tableIdx]) {
    POINTS_CACHE[tableIdx] = POINTS[tableIdx].map(([x, y]) => [hexToBigInt(x), hexToBigInt(y)]);
  }
  return POINTS_CACHE[tableIdx][idx];
}

const SHIFT = [hexToBigInt(SHIFT_POINT.x), hexToBigInt(SHIFT_POINT.y), 1n];

function lookupAndAccumulate(acc, bits, tableIdx) {
  const CHUNK = 4;
  for (let i = 0; i * CHUNK < bits.length; i++) {
    let offset = 0;
    for (let j = 0; j < CHUNK; j++) {
      if (bits[i * CHUNK + j]) offset += 1 << j;
    }
    if (offset > 0) {
      const [px, py] = pointAt(tableIdx, i * 15 + offset - 1);
      acc = jacAdd(acc, [px, py, 1n]);
    }
  }
  return acc;
}

/**
 * Starkware Pedersen hash H(x, y)：
 * acc = shift_point；依次对 x[0..248)/x[248..252)/y[0..248)/y[248..252)
 * 按 4-bit 查表累加；结果 = acc.x。
 */
export function pedersenHash(x, y) {
  const xv = typeof x === 'bigint' ? x : hexToBigInt(x);
  const yv = typeof y === 'bigint' ? y : hexToBigInt(y);
  let acc = [SHIFT[0], SHIFT[1], SHIFT[2]];
  const xb = feltToBitsLE(xv, 252);
  const yb = feltToBitsLE(yv, 252);
  acc = lookupAndAccumulate(acc, xb.slice(0, 248), 0);
  acc = lookupAndAccumulate(acc, xb.slice(248, 252), 1);
  acc = lookupAndAccumulate(acc, yb.slice(0, 248), 2);
  acc = lookupAndAccumulate(acc, yb.slice(248, 252), 3);
  return jacToAffine(acc)[0]; // 仿射 x（雅可比 X ≠ 仿射 x，官方 .x() 为仿射）
}

/** Starknet 元素哈希：pedersen 链（初值 0，末尾并入长度）。 */
export function computeHashOnElements(elements) {
  let current = 0n;
  for (const e of elements) {
    current = pedersenHash(current, typeof e === 'bigint' ? e : hexToBigInt(e));
  }
  return pedersenHash(current, BigInt(elements.length));
}

// ---------------------------------------------------------------------------
// ECDSA（STARK curve）
// ---------------------------------------------------------------------------

function toDigestFelt(z) {
  const v = typeof z === 'bigint' ? z : hexToBigInt(z);
  if (v < 0n || v >= FELT_BOUND) throw new Error('stark: message hash out of felt range');
  return v;
}

function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

/** HMAC-keccak256 DRBG（RFC 6979 结构；确定性 nonce，与安全论证同 HMAC-SHA256）。 */
function hmacKeccak(key, msg) {
  const RATE = 136;
  let k = key;
  if (k.length > RATE) k = keccak256(k);
  const ipad = new Uint8Array(RATE);
  const opad = new Uint8Array(RATE);
  ipad.set(k);
  opad.set(k);
  for (let i = 0; i < RATE; i++) {
    ipad[i] ^= 0x36;
    opad[i] ^= 0x5c;
  }
  return keccak256(concatBytes(opad, keccak256(concatBytes(ipad, msg))));
}

function intTo32BytesBE(v) {
  const out = new Uint8Array(32);
  let x = v;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function deterministicK(priv, digest) {
  const x = intTo32BytesBE(priv);
  const h1 = intTo32BytesBE(digest);
  let v = new Uint8Array(32).fill(1);
  let k = new Uint8Array(32);
  k = hmacKeccak(k, concatBytes(v, new Uint8Array([0]), x, h1));
  v = hmacKeccak(k, v);
  k = hmacKeccak(k, concatBytes(v, new Uint8Array([1]), x, h1));
  v = hmacKeccak(k, v);
  for (;;) {
    v = hmacKeccak(k, v);
    const cand = bytesToBigInt(v);
    if (cand > 0n && cand < EC_ORDER_N) return cand;
    k = hmacKeccak(k, concatBytes(v, new Uint8Array([0])));
    v = hmacKeccak(k, v);
  }
}

/**
 * ECDSA 签名（STARK curve）。digest 为 felt（< 2^251）。
 * @returns {{r: bigint, s: bigint}}（确定性 k；不强制 low-s——Starknet 语义）
 */
export function ecSign(digest, priv) {
  const z = toDigestFelt(digest);
  const d = typeof priv === 'bigint' ? priv : hexToBigInt(priv);
  if (d <= 0n || d >= EC_ORDER_N) throw new Error('stark: private key out of range');
  for (;;) {
    const k = deterministicK(d, z);
    const R = jacToAffine(jacMul(k, [GENERATOR.x, GENERATOR.y, 1n]));
    if (!R) continue;
    const r = modN(R[0]);
    if (r === 0n) continue;
    const s = modN(modInverse(k, EC_ORDER_N) * (z + d * r));
    if (s === 0n) continue;
    return { r, s };
  }
}

/** ECDSA 验证（公钥 = x 坐标 felt；语义同 starknet-crypto：±Q 两种符号任一匹配）。 */
export function ecVerify(pubX, digest, r, s) {
  const z = toDigestFelt(digest);
  const qx = typeof pubX === 'bigint' ? pubX : hexToBigInt(pubX);
  const rr = typeof r === 'bigint' ? r : hexToBigInt(r);
  const ss = typeof s === 'bigint' ? s : hexToBigInt(s);
  if (qx <= 0n || qx >= FELT_BOUND) return false;
  if (rr <= 0n || rr >= EC_ORDER_N || ss <= 0n || ss >= EC_ORDER_N) return false;
  const Q = decompressX(qx);
  if (!Q) return false;
  const w = modInverse(ss, EC_ORDER_N);
  const u1 = modN(z * w);
  const u2 = modN(rr * w);
  const zwG = jacMul(u1, [GENERATOR.x, GENERATOR.y, 1n]);
  // y 坐标只有 x 坐标公钥：官方实现按 +Q 与 −Q 两个符号分别核对 R.x == r。
  for (const q of [Q, [Q[0], modP(FIELD_P - Q[1]), 1n]]) {
    const affine = jacToAffine(jacAdd(zwG, jacMul(u2, q)));
    if (affine && modN(affine[0]) === rr) return true;
  }
  return false;
}

/**
 * ECDSA 公钥恢复（recovery id v ∈ {0,1}；dev 链/工具用）。
 * @returns {bigint} 公钥 x 坐标
 */
export function ecRecover(digest, r, s, v) {
  const z = toDigestFelt(digest);
  const rr = typeof r === 'bigint' ? r : hexToBigInt(r);
  const ss = typeof s === 'bigint' ? s : hexToBigInt(s);
  if (rr <= 0n || rr >= EC_ORDER_N || ss <= 0n || ss >= EC_ORDER_N) throw new Error('stark: bad signature');
  if (v !== 0 && v !== 1) throw new Error('stark: bad recovery id');
  const rInv = modInverse(rr, EC_ORDER_N);
  for (const x of [rr, rr + EC_ORDER_N]) {
    if (x >= FIELD_P) break;
    const R = decompressX(x);
    if (!R) continue;
    let [ry] = [R[1]];
    if (Number(ry & 1n) !== v) {
      ry = FIELD_P - ry;
    }
    const q = jacMul(rInv, jacAdd(jacMul(ss, [x, ry, 1n]), jacMul(modN(EC_ORDER_N - z), [GENERATOR.x, GENERATOR.y, 1n])));
    const affine = jacToAffine(q);
    if (!affine) continue;
    return affine[0];
  }
  throw new Error('stark: recovery failed');
}

/** 随机私钥（生态惯例：< 2^125，grind 等效）。 */
export function generatePrivateKey() {
  for (;;) {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    const v = bytesToBigInt(bytes) & (2n ** 125n - 1n);
    if (v > 0n && v < EC_ORDER_N) return v;
  }
}

// ---------------------------------------------------------------------------
// Starknet 账户地址推导
// ---------------------------------------------------------------------------

const CONTRACT_ADDRESS_PREFIX = encodeShortString('STARKNET_CONTRACT_ADDRESS');

/**
 * Starknet 账户合约地址（UDC/公式同 cairo-lang calculate_contract_address）：
 * addr = computeHashOnElements([prefix, deployer, salt, classHash,
 * computeHashOnElements(constructorCalldata)]) mod (2^251 − 256)。
 */
export function calculateContractAddress({ salt, classHash, constructorCalldata = [], deployerAddress = 0n }) {
  const calldata = constructorCalldata.map((c) => (typeof c === 'bigint' ? c : hexToBigInt(c)));
  const calldataHash = computeHashOnElements(calldata);
  const raw = computeHashOnElements([
    CONTRACT_ADDRESS_PREFIX,
    toFelt(deployerAddress),
    toFelt(salt),
    toFelt(classHash),
    calldataHash,
  ]);
  return raw % ADDR_BOUND;
}

/** 64 位补齐小写 hex（Starknet 地址展示惯例）。 */
export function padAddress(addr) {
  const v = typeof addr === 'bigint' ? addr : hexToBigInt(addr);
  return '0x' + v.toString(16).padStart(64, '0');
}

/** Starknet 风格校验和地址（starknet.js 同算法：完整 keccak256(补齐地址 32 字节) 锚定大小写，不掩码）。 */
export function toChecksumAddress(addr) {
  const padded = padAddress(addr).slice(2);
  const hashHex = bytesToHex(keccak256(hexToBytes(padded))).slice(2).padStart(64, '0');
  let out = '0x';
  for (let i = 0; i < padded.length; i++) {
    const c = padded[i];
    if (c >= 'a' && c <= 'f' && parseInt(hashHex[i], 16) >= 8) out += c.toUpperCase();
    else out += c;
  }
  return out;
}

export function isAddress(addr) {
  try {
    const v = hexToBigInt(addr);
    return /^0x/.test(String(addr)) && v >= 0n && v < ADDR_BOUND;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// 交易哈希（invoke v1）
// ---------------------------------------------------------------------------

export const TRANSACTION_HASH_PREFIX_INVOKE = encodeShortString('invoke');

/**
 * invoke v1 交易哈希（cairo-lang hash_transaction 语义）：
 * computeHashOnElements([prefix('invoke'), version, sender, entry_point(=0),
 * calldataHash, maxFee, chainId, nonce])。
 */
export function calculateInvokeTransactionHash({ version = 1n, senderAddress, calldata = [], maxFee, chainId, nonce }) {
  const calldataHash = computeHashOnElements(calldata.map((c) => (typeof c === 'bigint' ? c : hexToBigInt(c))));
  return computeHashOnElements([
    TRANSACTION_HASH_PREFIX_INVOKE,
    toFelt(version),
    toFelt(senderAddress),
    0n,
    calldataHash,
    toFelt(maxFee),
    toFelt(chainId),
    toFelt(nonce),
  ]);
}
