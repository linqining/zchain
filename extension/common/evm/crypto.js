// =============================================================================
// extension/common/evm/crypto.js — EVM 账户层密码学（Extension 0.5）
//
// 自包含、零依赖、零远程代码（CSP 安全）：keccak256、secp256k1（Jacobian
// 坐标 ECDSA：签名/验证/恢复）、RLP、EIP-155 交易签名与 sender 恢复、
// EIP-55 校验和地址、HMAC-Keccak256 DRBG（RFC 6979 结构的确定性 nonce）。
//
// 边界说明（如实）：本模块服务于 0.5 新增的 EVM 兼容账户层；既有 ZChain
// 路径的密码学边界仍是 wallet-core WASM（本文件不参与那条路径）。本模块
// 的正确性由公共测试向量钉住（tests/evm/crypto.test.js）：
//   - keccak256("")/EIP-155 signing hash（规范给定的哈希值）
//   - EIP-155 规范示例交易：由规范私钥 0x46…46 签出的完整 raw tx 字节 +
//     sender 恢复一致性
//   - G 点已知向量（priv=1 → 著名公钥 x 坐标）+ 地址推导已知向量
//   - 确定性 nonce DRBG 的行为性质测试
// k 的生成按 RFC 6979 的 HMAC-DRBG 结构实现，哈希函数用 keccak256
// （HMAC 结构通用；非 RFC 6979 规定的 SHA 族——确定性性质不变，安全论证
// 相同，代码内注明）。
// =============================================================================

// ---------------------------------------------------------------------------
// hex / bytes 工具
// ---------------------------------------------------------------------------

export function bytesToHex(bytes) {
  let out = '0x';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function hexToBytes(hex) {
  if (typeof hex !== 'string') throw new Error('hexToBytes: not a string');
  const h = hex.toLowerCase().replace(/^0x/, '');
  if (h.length % 2 !== 0 || /[^0-9a-f]/.test(h)) throw new Error('hexToBytes: bad hex');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function isHex(hex) {
  return typeof hex === 'string' && /^0x[0-9a-fA-F]*$/.test(hex) && hex.length % 2 === 0;
}

export function utf8ToBytes(str) {
  return new TextEncoder().encode(str);
}

export function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

export function bigIntToBytes(value, length = 0) {
  if (value === 0n) return new Uint8Array(length);
  let v = value < 0n ? -value : value; // 调用方负责符号处理
  let hex = v.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const bytes = hexToBytes(hex);
  if (bytes.length < length) return concatBytes(new Uint8Array(length - bytes.length), bytes);
  if (length > 0 && bytes.length > length) throw new Error('bigIntToBytes: overflow');
  return bytes;
}

export function bytesToBigInt(bytes) {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

/** 最小 big-endian 字节（0 → 空字节串，RLP 整数语义）。 */
function intBytes(v) {
  if (v === 0n) return new Uint8Array(0);
  return bigIntToBytes(v);
}

// ---------------------------------------------------------------------------
// keccak256（Keccak-f[1600]，rate=136，Keccak 原版 padding 0x01…0x80）
// 移植自广泛使用的紧凑参考实现（mjosaarinen/tiny_keccak 风格），常量与
// 轮转表为标准值。
// ---------------------------------------------------------------------------

const KECCAK_RATE = 136;
const KECCAK_RC = [
  0x0000000000000001n, 0x0000000000008082n, 0x800000000000808an, 0x8000000080008000n,
  0x000000000000808bn, 0x0000000080000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x000000000000008an, 0x0000000000000088n, 0x0000000080008009n, 0x000000008000000an,
  0x000000008000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x000000000000800an, 0x800000008000000an,
  0x8000000080008081n, 0x8000000000008080n, 0x0000000080000001n, 0x8000000080008008n,
];
const KECCAK_ROTC = [1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44];
const KECCAK_PILN = [10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1];
const MASK64 = 0xffffffffffffffffn;

function rotl64(v, n) {
  const b = BigInt(n);
  return ((v << b) | (v >> (64n - b))) & MASK64;
}

function keccakF(st) {
  const bc = new Array(5).fill(0n);
  for (let round = 0; round < 24; round++) {
    // theta
    for (let i = 0; i < 5; i++) bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
    for (let i = 0; i < 5; i++) {
      const t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
      for (let j = 0; j < 25; j += 5) st[j + i] = (st[j + i] ^ t) & MASK64;
    }
    // rho + pi
    let t = st[1];
    for (let i = 0; i < 24; i++) {
      const j = KECCAK_PILN[i];
      const tmp = st[j];
      st[j] = rotl64(t, KECCAK_ROTC[i]);
      t = tmp;
    }
    // chi
    for (let j = 0; j < 25; j += 5) {
      for (let i = 0; i < 5; i++) bc[i] = st[j + i];
      for (let i = 0; i < 5; i++) st[j + i] = (st[j + i] ^ ((~bc[(i + 1) % 5]) & bc[(i + 2) % 5])) & MASK64;
    }
    // iota
    st[0] = (st[0] ^ KECCAK_RC[round]) & MASK64;
  }
}

export function keccak256(input) {
  const msg = input instanceof Uint8Array ? input : utf8ToBytes(String(input));
  const st = new Array(25).fill(0n);
  const loadLane = (bytes, off) => {
    let lane = 0n;
    for (let i = 7; i >= 0; i--) lane = (lane << 8n) | BigInt(bytes[off + i] ?? 0);
    return lane;
  };
  let i = 0;
  for (; i + KECCAK_RATE <= msg.length; i += KECCAK_RATE) {
    for (let j = 0; j < KECCAK_RATE / 8; j++) st[j] ^= loadLane(msg, i + j * 8);
    keccakF(st);
  }
  // final block + Keccak padding（0x01 … 0x80）
  const block = new Uint8Array(KECCAK_RATE);
  block.set(msg.subarray(i));
  block[msg.length - i] ^= 0x01;
  block[KECCAK_RATE - 1] ^= 0x80;
  for (let j = 0; j < KECCAK_RATE / 8; j++) st[j] ^= loadLane(block, j * 8);
  keccakF(st);
  const out = new Uint8Array(32);
  for (let j = 0; j < 4; j++) {
    let lane = st[j];
    for (let k = 0; k < 8; k++) {
      out[j * 8 + k] = Number(lane & 0xffn);
      lane >>= 8n;
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// HMAC-Keccak256（RFC 2104 结构；块大小 = keccak rate = 136）
// ---------------------------------------------------------------------------

function hmacKeccak256(key, msg) {
  let k = key;
  if (k.length > KECCAK_RATE) k = keccak256(k);
  const ipad = new Uint8Array(KECCAK_RATE);
  const opad = new Uint8Array(KECCAK_RATE);
  ipad.set(k);
  opad.set(k);
  for (let i = 0; i < KECCAK_RATE; i++) {
    ipad[i] ^= 0x36;
    opad[i] ^= 0x5c;
  }
  return keccak256(concatBytes(opad, keccak256(concatBytes(ipad, msg))));
}

// ---------------------------------------------------------------------------
// secp256k1（Jacobian 坐标；a=0, b=7）
// ---------------------------------------------------------------------------

export const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const SECP256K1_GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const SECP256K1_GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
const HALF_N = SECP256K1_N >> 1n;

function mod(a, m = SECP256K1_P) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

/** 扩展欧几里得模逆。 */
export function modInverse(a, m) {
  let [old_r, r] = [mod(a, m), m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new Error('modInverse: not invertible');
  return mod(old_s, m);
}

const INF = [0n, 1n, 0n]; // Jacobian 无穷远点

function jacDouble([x, y, z]) {
  if (y === 0n || z === 0n) return INF;
  const ysq = mod(y * y);
  const s = mod(4n * x * ysq);
  const m = mod(3n * x * x); // a = 0
  const x3 = mod(m * m - 2n * s);
  const y3 = mod(m * (s - x3) - 8n * ysq * ysq);
  const z3 = mod(2n * y * z);
  return [x3, y3, z3];
}

function jacAdd(p1, p2) {
  let [x1, y1, z1] = p1;
  let [x2, y2, z2] = p2;
  if (z1 === 0n) return p2;
  if (z2 === 0n) return p1;
  const z1z1 = mod(z1 * z1);
  const z2z2 = mod(z2 * z2);
  const u1 = mod(x1 * z2z2);
  const u2 = mod(x2 * z1z1);
  const s1 = mod(y1 * z2 * z2z2);
  const s2 = mod(y2 * z1 * z1z1);
  if (u1 === u2) {
    if (s1 !== s2) return INF;
    return jacDouble(p1);
  }
  const h = mod(u2 - u1);
  const r = mod(s2 - s1);
  const hh = mod(h * h);
  const hhh = mod(h * hh);
  const u1hh = mod(u1 * hh);
  const x3 = mod(r * r - hhh - 2n * u1hh);
  const y3 = mod(r * (u1hh - x3) - s1 * hhh);
  const z3 = mod(z1 * z2 * h);
  return [x3, y3, z3];
}

function jacMul(k, point) {
  let n = mod(k, SECP256K1_N);
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
  const zinv = modInverse(z, SECP256K1_P);
  const zinv2 = mod(zinv * zinv);
  return [mod(x * zinv2), mod(y * zinv2 * zinv)];
}

const G_JAC = [SECP256K1_GX, SECP256K1_GY, 1n];

/** 私钥入参归一：hex 字符串 / Uint8Array / BigInt → BigInt。 */
function toPrivBigint(priv) {
  if (typeof priv === 'bigint') return priv;
  if (typeof priv === 'string') return bytesToBigInt(hexToBytes(priv));
  return bytesToBigInt(priv);
}

/** digest 入参归一：hex 字符串 / Uint8Array → 32 字节。 */
function toDigestBytes(digest) {
  return typeof digest === 'string' ? hexToBytes(digest) : digest;
}

/** 私钥（32 字节或 BigInt）→ 非压缩公钥 65 字节（04 ‖ X ‖ Y）。 */
export function privateToPublicKey(priv) {
  const d = toPrivBigint(priv);
  if (d <= 0n || d >= SECP256K1_N) throw new Error('secp256k1: private key out of range');
  const [x, y] = jacToAffine(jacMul(d, G_JAC));
  return concatBytes(new Uint8Array([4]), bigIntToBytes(x, 32), bigIntToBytes(y, 32));
}

/** 非压缩公钥 → EVM 地址（keccak(pubkey)[12..32]），小写 hex。 */
export function addressFromPublicKey(pubUncompressed) {
  if (pubUncompressed.length !== 65 || pubUncompressed[0] !== 4) {
    throw new Error('addressFromPublicKey: expect uncompressed 65-byte pubkey');
  }
  const hash = keccak256(pubUncompressed.subarray(1));
  return bytesToHex(hash.subarray(12));
}

/** EIP-55 校验和地址。 */
export function toChecksumAddress(addr) {
  const a = String(addr).toLowerCase().replace(/^0x/, '');
  if (a.length !== 40 || /[^0-9a-f]/.test(a)) throw new Error('toChecksumAddress: bad address');
  const hash = bytesToHex(keccak256(utf8ToBytes(a))).slice(2);
  let out = '0x';
  for (let i = 0; i < 40; i++) {
    const c = a[i];
    if (c >= 'a' && c <= 'f') {
      out += parseInt(hash[i], 16) >= 8 ? c.toUpperCase() : c;
    } else {
      out += c;
    }
  }
  return out;
}

export function isAddress(addr) {
  return typeof addr === 'string' && /^0x[0-9a-fA-F]{40}$/.test(addr);
}

// ---------------------------------------------------------------------------
// ECDSA 签名 / 验证 / 恢复（digest = 32 字节）
// ---------------------------------------------------------------------------

/** RFC 6979 结构的确定性 nonce（HMAC-DRBG，H = keccak256）。 */
function deterministicK(privBig, digest) {
  const x = bigIntToBytes(privBig, 32);
  const h1 = digest instanceof Uint8Array ? digest : hexToBytes(digest);
  // bits2octets：h1 mod N，32 字节（qlen = 256）
  const h = bigIntToBytes(mod(bytesToBigInt(h1), SECP256K1_N), 32);
  let v = new Uint8Array(32).fill(1);
  let k = new Uint8Array(32);
  k = hmacKeccak256(k, concatBytes(v, new Uint8Array([0]), x, h));
  v = hmacKeccak256(k, v);
  k = hmacKeccak256(k, concatBytes(v, new Uint8Array([1]), x, h));
  v = hmacKeccak256(k, v);
  for (;;) {
    v = hmacKeccak256(k, v);
    const cand = bytesToBigInt(v);
    if (cand > 0n && cand < SECP256K1_N) return cand;
    k = hmacKeccak256(k, concatBytes(v, new Uint8Array([0])));
    v = hmacKeccak256(k, v);
  }
}

/**
 * ECDSA 签名（low-s 规范化）。digest 为 32 字节。
 * @returns {{r: bigint, s: bigint, recovery: number}} recovery ∈ {0,1}
 */
export function ecSign(digest, priv) {
  const d = toPrivBigint(priv);
  if (d <= 0n || d >= SECP256K1_N) throw new Error('ecSign: private key out of range');
  digest = toDigestBytes(digest);
  let h = bytesToBigInt(digest);
  if (h >= SECP256K1_N) h -= SECP256K1_N;
  for (;;) {
    const k = deterministicK(d, digest);
    const R = jacToAffine(jacMul(k, G_JAC));
    if (!R) continue;
    const r = mod(R[0], SECP256K1_N);
    if (r === 0n) continue;
    let s = mod(modInverse(k, SECP256K1_N) * (h + d * r), SECP256K1_N);
    if (s === 0n) continue;
    let recovery = Number(R[1] & 1n);
    if (s > HALF_N) {
      s = SECP256K1_N - s;
      recovery ^= 1;
    }
    return { r, s, recovery };
  }
}

/** ECDSA 验证（内部用；恢复路径已覆盖主用途）。 */
export function ecVerify(digest, r, s, pubUncompressed) {
  digest = toDigestBytes(digest);
  let h = bytesToBigInt(digest);
  if (h >= SECP256K1_N) h -= SECP256K1_N;
  const pub = pubUncompressed instanceof Uint8Array
    ? jacToAffine([bytesToBigInt(pubUncompressed.subarray(1, 33)), bytesToBigInt(pubUncompressed.subarray(33)), 1n])
    : pubUncompressed;
  if (!pub || r <= 0n || r >= SECP256K1_N || s <= 0n || s >= SECP256K1_N) return false;
  const w = modInverse(s, SECP256K1_N);
  const u1 = mod(h * w, SECP256K1_N);
  const u2 = mod(r * w, SECP256K1_N);
  const point = jacAdd(jacMul(u1, G_JAC), jacMul(u2, [pub[0], pub[1], 1n]));
  const affine = jacToAffine(point);
  if (!affine) return false;
  return mod(affine[0], SECP256K1_N) === mod(r, SECP256K1_N);
}

/** ECDSA 公钥恢复（recovery ∈ {0,1}）。返回非压缩公钥 65 字节。 */
export function ecRecover(digest, r, s, recovery) {
  digest = toDigestBytes(digest);
  let h = bytesToBigInt(digest);
  if (h >= SECP256K1_N) h -= SECP256K1_N;
  if (r <= 0n || r >= SECP256K1_N || s <= 0n || s >= SECP256K1_N) throw new Error('ecRecover: bad signature');
  if (recovery !== 0 && recovery !== 1) throw new Error('ecRecover: bad recovery id');
  const x = r; // secp256k1: r < N < P，可直接作为 x 坐标候选
  const ysq = mod(x * x * x + 7n);
  // p ≡ 3 (mod 4) → 平方根 = y^((p+1)/4)
  let y = modPow(ysq, (SECP256K1_P + 1n) / 4n, SECP256K1_P);
  if (mod(y * y) !== ysq) throw new Error('ecRecover: point not on curve');
  if (Number(y & 1n) !== recovery) y = SECP256K1_P - y;
  const R = [x, y, 1n];
  const rInv = modInverse(r, SECP256K1_N);
  const q = jacMul(rInv, jacAdd(jacMul(s, R), jacMul(mod(SECP256K1_N - h, SECP256K1_N), G_JAC)));
  const affine = jacToAffine(q);
  if (!affine) throw new Error('ecRecover: recovered infinity');
  return concatBytes(new Uint8Array([4]), bigIntToBytes(affine[0], 32), bigIntToBytes(affine[1], 32));
}

function modPow(base, exp, m) {
  let result = 1n;
  let b = mod(base, m);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = mod(result * b, m);
    b = mod(b * b, m);
    e >>= 1n;
  }
  return result;
}

/** crypto.getRandomValues 生成随机私钥（32 字节，模 N 范围内）。 */
export function generatePrivateKeyBytes() {
  for (;;) {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    const v = bytesToBigInt(bytes);
    if (v > 0n && v < SECP256K1_N) return bytes;
  }
}

// ---------------------------------------------------------------------------
// RLP
// ---------------------------------------------------------------------------

function rlpEncodeItem(item) {
  if (item instanceof Uint8Array) {
    if (item.length === 1 && item[0] < 0x80) return item;
    return concatBytes(rlpLengthPrefix(item.length, 0x80), item);
  }
  if (Array.isArray(item)) {
    const payload = concatBytes(...item.map(rlpEncodeItem));
    return concatBytes(rlpLengthPrefix(payload.length, 0xc0), payload);
  }
  throw new Error('rlpEncode: unsupported item');
}

function rlpLengthPrefix(len, offset) {
  if (len < 56) return new Uint8Array([offset + len]);
  const lenBytes = bigIntToBytes(BigInt(len));
  return concatBytes(new Uint8Array([offset + 55 + lenBytes.length]), lenBytes);
}

export function rlpEncode(item) {
  return rlpEncodeItem(item);
}

export function rlpDecode(bytes) {
  const [item, consumed] = rlpDecodeAt(bytes, 0);
  if (consumed !== bytes.length) throw new Error('rlpDecode: trailing bytes');
  return item;
}

function rlpDecodeAt(bytes, pos) {
  if (pos >= bytes.length) throw new Error('rlpDecode: unexpected end');
  const prefix = bytes[pos];
  if (prefix < 0x80) return [new Uint8Array([prefix]), pos + 1];
  if (prefix < 0xb8) {
    const len = prefix - 0x80;
    return [bytes.subarray(pos + 1, pos + 1 + len), pos + 1 + len];
  }
  if (prefix < 0xc0) {
    const lenOfLen = prefix - 0xb7;
    const len = Number(bytesToBigInt(bytes.subarray(pos + 1, pos + 1 + lenOfLen)));
    const start = pos + 1 + lenOfLen;
    return [bytes.subarray(start, start + len), start + len];
  }
  const isLong = prefix < 0xf8;
  let len, start;
  if (isLong) {
    len = prefix - 0xc0;
    start = pos + 1;
  } else {
    const lenOfLen = prefix - 0xf7;
    len = Number(bytesToBigInt(bytes.subarray(pos + 1, pos + 1 + lenOfLen)));
    start = pos + 1 + lenOfLen;
  }
  const end = start + len;
  if (end > bytes.length) throw new Error('rlpDecode: length out of range');
  const items = [];
  let p = start;
  while (p < end) {
    const [item, next] = rlpDecodeAt(bytes, p);
    items.push(item);
    p = next;
  }
  if (p !== end) throw new Error('rlpDecode: list length mismatch');
  return [items, end];
}

// ---------------------------------------------------------------------------
// EIP-155 legacy 交易签名
// ---------------------------------------------------------------------------

function pad32Hex(hexNo0x) {
  return hexToBytes(hexNo0x.padStart(64, '0'));
}

/**
 * 签名交易（EIP-155 legacy）。
 * @param {object} tx {nonce, gasPrice, gasLimit, to ('0x…'|null), value, data (hex), chainId}
 * @param {Uint8Array|bigint} priv
 * @returns {{raw: string, hash: string, v: bigint, r: bigint, s: bigint}} raw/hash 为 0x 前缀 hex
 */
export function signLegacyTransaction(tx, priv) {
  const d = toPrivBigint(priv);
  const chainId = BigInt(tx.chainId);
  if (chainId <= 0n) throw new Error('signLegacyTransaction: bad chainId');
  const nonce = BigInt(tx.nonce);
  const gasPrice = BigInt(tx.gasPrice);
  const gasLimit = BigInt(tx.gasLimit);
  const value = BigInt(tx.value);
  const data = typeof tx.data === 'string' ? hexToBytes(tx.data) : (tx.data ?? new Uint8Array(0));
  const to = tx.to ? hexToBytes(tx.to) : new Uint8Array(0);
  if (to.length !== 0 && to.length !== 20) throw new Error('signLegacyTransaction: bad `to`');

  const unsigned = [intBytes(nonce), intBytes(gasPrice), intBytes(gasLimit), to, intBytes(value), data,
    intBytes(chainId), new Uint8Array(0), new Uint8Array(0)];
  const digest = keccak256(rlpEncode(unsigned));
  const { r, s, recovery } = ecSign(digest, d);
  const v = 35n + chainId * 2n + BigInt(recovery);
  const signed = [intBytes(nonce), intBytes(gasPrice), intBytes(gasLimit), to, intBytes(value), data,
    intBytes(v), pad32Hex(r.toString(16)), pad32Hex(s.toString(16))];
  const raw = rlpEncode(signed);
  return { raw: bytesToHex(raw), hash: bytesToHex(keccak256(raw)), v, r, s };
}

/**
 * 解析 raw 交易并恢复 sender（dev 链 / 预览用）。
 * @returns {{nonce, gasPrice, gasLimit, to, value, data, chainId, from, hash}}
 */
export function parseAndRecoverTransaction(rawHex) {
  const raw = hexToBytes(rawHex);
  const items = rlpDecode(raw);
  if (!Array.isArray(items) || items.length !== 9) throw new Error('parseTx: expect legacy tx with 9 fields');
  const [nonce, gasPrice, gasLimit, to, value, data, vB, rB, sB] = items;
  const v = bytesToBigInt(vB);
  const r = bytesToBigInt(rB);
  const s = bytesToBigInt(sB);
  let chainId, recovery;
  if (v >= 35n) {
    chainId = (v - 35n) >> 1n;
    recovery = Number(v - 35n - chainId * 2n);
  } else if (v === 27n || v === 28n) {
    chainId = null;
    recovery = Number(v - 27n);
  } else {
    throw new Error('parseTx: bad v');
  }
  const unsigned = chainId !== null
    ? [nonce, gasPrice, gasLimit, to, value, data, intBytes(chainId), new Uint8Array(0), new Uint8Array(0)]
    : [nonce, gasPrice, gasLimit, to, value, data];
  const digest = keccak256(rlpEncode(unsigned));
  const pub = ecRecover(digest, r, s, recovery);
  return {
    nonce: bytesToBigInt(nonce),
    gasPrice: bytesToBigInt(gasPrice),
    gasLimit: bytesToBigInt(gasLimit),
    to: to.length === 20 ? bytesToHex(to) : null,
    value: bytesToBigInt(value),
    data: bytesToHex(data),
    chainId,
    from: toChecksumAddress(addressFromPublicKey(pub)),
    hash: bytesToHex(keccak256(raw)),
  };
}

// ---------------------------------------------------------------------------
// 数值格式化（十进制字符串 ⇄ wei，安全整数边界外用字符串/BigInt）
// ---------------------------------------------------------------------------

/** wei → 十进制字符串（按 decimals 小数位，去尾零）。 */
export function formatUnits(wei, decimals = 18) {
  let v = typeof wei === 'bigint' ? wei : BigInt(String(wei).replace(/^0x/i, '') || '0');
  const neg = v < 0n;
  if (neg) v = -v;
  const base = 10n ** BigInt(decimals);
  const whole = v / base;
  const frac = (v % base).toString().padStart(decimals, '0').replace(/0+$/, '');
  const s = frac ? `${whole}.${frac}` : whole.toString();
  return neg ? `-${s}` : s;
}

/** 十进制（或 0x hex）字符串 → wei BigInt。 */
export function parseUnits(value, decimals = 18) {
  const s = String(value).trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  const m = /^(-?)(\d+)(?:\.(\d+))?$/.exec(s);
  if (!m) throw new Error('parseUnits: bad decimal');
  const sign = m[1] === '-' ? -1n : 1n;
  const whole = BigInt(m[2]);
  let frac = (m[3] ?? '').slice(0, decimals).padEnd(decimals, '0');
  const fracVal = frac ? BigInt(frac) : 0n;
  return sign * (whole * 10n ** BigInt(decimals) + fracVal);
}

// ---------------------------------------------------------------------------
// ABI 编解码（uintN/intN/address/bool/bytes/bytesN/string + 1 维数组）
// ---------------------------------------------------------------------------

const FUNCTION_SELECTOR_CACHE = new Map();

export function functionSelector(signature) {
  let sel = FUNCTION_SELECTOR_CACHE.get(signature);
  if (!sel) {
    sel = bytesToHex(keccak256(utf8ToBytes(signature))).slice(0, 10); // 0x + 4 字节
    FUNCTION_SELECTOR_CACHE.set(signature, sel);
  }
  return sel;
}

function parseAbiType(type) {
  const m = /^(.*?)(\[(\d*)\])$/.exec(type);
  if (m) {
    return { array: true, length: m[3] === '' ? null : Number(m[3]), item: parseAbiType(m[1]) };
  }
  const base = /^(uint|int|bytes|bytes|address|bool|string)(\d+)?$/.exec(type);
  if (!base) throw new Error(`abi: unsupported type ${type}`);
  return { array: false, kind: base[1], size: base[2] ? Number(base[2]) : null };
}

function isDynamicType(t) {
  const p = parseAbiType(t);
  if (p.array) return p.length === null || isDynamicType(p.item.kind + (p.item.size ?? ''));
  return p.kind === 'bytes' || p.kind === 'string';
}

function encodeStatic(t, value) {
  const p = parseAbiType(t);
  if (p.array) {
    if (p.length === null) throw new Error('abi: dynamic array is not static');
    if (!Array.isArray(value) || value.length !== p.length) throw new Error('abi: fixed array length mismatch');
    return concatBytes(...value.map((v) => encodeStatic(p.item.kind + (p.item.size ?? ''), v)));
  }
  switch (p.kind) {
    case 'uint': {
      const v = BigInt(value);
      if (v < 0n || v >= 2n ** BigInt(p.size ?? 256)) throw new Error('abi: uint overflow');
      return bigIntToBytes(v, 32);
    }
    case 'int': {
      let v = BigInt(value);
      const bits = BigInt(p.size ?? 256);
      if (v < -(2n ** (bits - 1n)) || v >= 2n ** (bits - 1n)) throw new Error('abi: int overflow');
      if (v < 0n) v += 2n ** bits; // 二补码
      return bigIntToBytes(v, 32);
    }
    case 'address': {
      const bytes = hexToBytes(value);
      if (bytes.length !== 20) throw new Error('abi: bad address');
      return concatBytes(new Uint8Array(12), bytes);
    }
    case 'bool':
      return bigIntToBytes(value === true || value === 'true' || BigInt(value) === 1n ? 1n : 0n, 32);
    case 'bytes': {
      const bytes = hexToBytes(value);
      if (bytes.length > p.size) throw new Error('abi: bytesN overflow');
      return concatBytes(bytes, new Uint8Array(32 - bytes.length));
    }
    case 'string':
    default:
      throw new Error('abi: not a static type');
  }
}

function encodeDynamic(t, value) {
  const p = parseAbiType(t);
  if (p.kind === 'bytes') {
    const bytes = hexToBytes(value);
    return concatBytes(bigIntToBytes(BigInt(bytes.length), 32), padRight32(bytes));
  }
  if (p.kind === 'string') {
    const bytes = utf8ToBytes(String(value));
    return concatBytes(bigIntToBytes(BigInt(bytes.length), 32), padRight32(bytes));
  }
  if (p.array && p.length === null) {
    if (!Array.isArray(value)) throw new Error('abi: expect array value');
    const elems = encodeTuple(Array(value.length).fill(p.item.kind + (p.item.size ?? '')), value);
    return concatBytes(bigIntToBytes(BigInt(value.length), 32), elems);
  }
  throw new Error('abi: not a dynamic type');
}

function padRight32(bytes) {
  const rem = bytes.length % 32;
  return rem === 0 ? bytes : concatBytes(bytes, new Uint8Array(32 - rem));
}

/** 编码参数区（不含 selector）。返回 Uint8Array。 */
export function encodeTuple(types, values) {
  if (types.length !== values.length) throw new Error('abi: arity mismatch');
  const heads = [];
  const tails = [];
  for (let i = 0; i < types.length; i++) {
    if (isDynamicType(types[i])) {
      heads.push(null);
      tails.push(encodeDynamic(types[i], values[i]));
    } else {
      const enc = encodeStatic(types[i], values[i]);
      heads.push(enc);
      tails.push(null);
    }
  }
  let headSize = heads.reduce((n, h) => n + (h ? h.length : 32), 0);
  // 先算 tail 累计偏移，再回填动态 offset
  let acc = headSize;
  for (let i = 0; i < heads.length; i++) {
    if (heads[i] === null) {
      heads[i] = bigIntToBytes(BigInt(acc), 32);
      acc += tails[i].length;
    }
  }
  return concatBytes(...heads.filter(Boolean), ...tails.filter(Boolean));
}

function decodeStatic(t, data, offset) {
  const p = parseAbiType(t);
  if (p.array && p.length !== null) {
    const parts = [];
    for (let i = 0; i < p.length; i++) {
      parts.push(decodeStatic(p.item.kind + (p.item.size ?? ''), data, offset + i * 32));
    }
    return parts;
  }
  const word = data.subarray(offset, offset + 32);
  if (word.length < 32) throw new Error('abi: decode out of range');
  switch (p.kind) {
    case 'uint': {
      const v = bytesToBigInt(word);
      return v.toString();
    }
    case 'int': {
      const bits = BigInt(p.size ?? 256);
      let v = bytesToBigInt(word);
      if (v >= 2n ** (bits - 1n)) v -= 2n ** bits;
      return v.toString();
    }
    case 'address':
      return toChecksumAddress(bytesToHex(word.subarray(12)));
    case 'bool':
      return bytesToBigInt(word) !== 0n;
    case 'bytes':
      return bytesToHex(word.subarray(0, p.size));
    default:
      throw new Error('abi: not a static type');
  }
}

function decodeDynamic(t, data, offset) {
  const p = parseAbiType(t);
  if (p.kind === 'bytes') {
    const len = Number(bytesToBigInt(data.subarray(offset, offset + 32)));
    return bytesToHex(data.subarray(offset + 32, offset + 32 + len));
  }
  if (p.kind === 'string') {
    const len = Number(bytesToBigInt(data.subarray(offset, offset + 32)));
    return new TextDecoder().decode(data.subarray(offset + 32, offset + 32 + len));
  }
  if (p.array && p.length === null) {
    const len = Number(bytesToBigInt(data.subarray(offset, offset + 32)));
    return decodeTuple(Array(len).fill(p.item.kind + (p.item.size ?? '')), data.subarray(offset + 32));
  }
  throw new Error('abi: not a dynamic type');
}

/** 解码参数区（types ↔ data）。返回解码值数组。 */
export function decodeTuple(types, dataHex) {
  const data = typeof dataHex === 'string' ? hexToBytes(dataHex) : dataHex;
  const out = [];
  let cursor = 0;
  for (const t of types) {
    if (isDynamicType(t)) {
      const rel = Number(bytesToBigInt(data.subarray(cursor, cursor + 32)));
      out.push(decodeDynamic(t, data, rel));
      cursor += 32;
    } else {
      const enc = decodeStatic(t, data, cursor);
      out.push(enc);
      const p = parseAbiType(t);
      cursor += p.array && p.length !== null ? p.length * 32 : 32;
    }
  }
  return out;
}

/** 组装合约调用 calldata（0x hex）。 */
export function encodeCall(signature, types, values) {
  return functionSelector(signature) + bytesToHex(encodeTuple(types, values)).slice(2);
}
