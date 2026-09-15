// =============================================================================
// extension/common/stark/account.js — Starknet 账户 keystore 与地址（Extension 0.6）
//
// keystore 复用 EVM 层同一 WebCrypto 方案（PBKDF2-SHA256 + AES-256-GCM），
// 但形状独立（version 'stark-1'）：address 字段 = Starknet 账户地址
// （UDC 公式推导），私钥为 felt（< 2^125，生态惯例），只存密文。
// 地址 = calculateContractAddress({salt, classHash, constructorCalldata:[pubkey]})
// —— 与 ArgentX/OZ 类账户构造参数一致（constructor 只收 pubkey）。
// =============================================================================

import { hexToBytes, bytesToHex } from '../evm/crypto.js';
import {
  generatePrivateKey, privateKeyToPublicKey, calculateContractAddress,
  toChecksumAddress, hexToBigInt, bigIntToHex, padAddress, isFelt,
} from './curve.js';

export const PBKDF2_ITERATIONS = 600_000;

const subtle = () => globalThis.crypto.subtle;

function assertCrypto() {
  if (typeof globalThis.crypto?.subtle?.importKey !== 'function') {
    throw new Error('WebCrypto subtle 不可用（需要安全上下文 / Node ≥ 20）');
  }
}

function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

function requirePassword(password) {
  if (typeof password !== 'string' || password.length < 8) {
    const e = new Error('口令至少 8 字符');
    e.code = 'InvalidArgument';
    throw e;
  }
}

async function deriveKey(password, saltBytes, iterations) {
  assertCrypto();
  const keyMaterial = await subtle().importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey'],
  );
  return subtle().deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

/** 私钥 felt → 32 字节 BE（keystore 内部表示）。 */
function feltTo32Bytes(privBig) {
  const out = new Uint8Array(32);
  let v = privBig;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function bytes32ToFelt(bytes) {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

/** 随机盐（felt，< 2^251）。 */
export function generateSalt() {
  const b = randomBytes(31);
  b[0] &= 0x7f; // < 2^248
  const v = bytes32ToFelt(b);
  return v === 0n ? 1n : v;
}

/**
 * 由私钥推导 Starknet 账户地址（ArgentX/OZ 形状：constructor_calldata = [pubkey]）。
 * @param {object} opts {privKey: bigint, salt: bigint, classHash: bigint|string}
 * @returns {{address: bigint, pubKey: bigint, salt: bigint}}
 */
export function deriveAccount({ privKey, salt, classHash }) {
  const d = typeof privKey === 'bigint' ? privKey : hexToBigInt(privKey);
  if (d <= 0n || d >= 2n ** 125n) throw new Error('stark account: private key out of range (< 2^125)');
  const pubKey = privateKeyToPublicKey(d);
  const cls = typeof classHash === 'bigint' ? classHash : hexToBigInt(classHash);
  const address = calculateContractAddress({
    salt, classHash: cls, constructorCalldata: [pubKey], deployerAddress: 0n,
  });
  return { address, pubKey, salt };
}

/**
 * 创建 Starknet 账户 keystore（随机私钥 + 随机盐 + 指定 class hash）。
 * @returns {Promise<{keystore, address, pubKey, salt, privateKey}>}
 *          privateKey 仅创建当次回执用，不落任何存储。
 */
export async function createStarkAccount(password, classHash, {
  iterations = PBKDF2_ITERATIONS, nowSec = Math.floor(Date.now() / 1000), labelSalt = null,
} = {}) {
  requirePassword(password);
  if (!isFelt(classHash) || hexToBigInt(classHash) === 0n) {
    const e = new Error('账户 class hash 非法');
    e.code = 'InvalidArgument';
    throw e;
  }
  const priv = generatePrivateKey();
  const salt = labelSalt ?? generateSalt();
  const { address, pubKey } = deriveAccount({ privKey: priv, salt, classHash });
  const keystore = await encryptToKeystore(priv, {
    password, salt, classHash, address, iterations, nowSec,
  });
  return { keystore, address: bigIntToHex(address), pubKey: bigIntToHex(pubKey), privateKey: bigIntToHex(priv) };
}

/** 私钥 felt → 加密 keystore（导入路径）。 */
export async function encryptToKeystore(privBig, {
  password, salt, classHash, address, iterations = PBKDF2_ITERATIONS, nowSec = Math.floor(Date.now() / 1000),
} = {}) {
  requirePassword(password);
  assertCrypto();
  const priv = typeof privBig === 'bigint' ? privBig : hexToBigInt(privBig);
  if (priv <= 0n || priv >= 2n ** 125n) {
    const e = new Error('私钥非法（需 < 2^125）');
    e.code = 'InvalidArgument';
    throw e;
  }
  const derived = deriveAccount({ privKey: priv, salt, classHash });
  const saltBytes = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveKey(password, saltBytes, iterations);
  const data = await subtle().encrypt({ name: 'AES-GCM', iv }, key, feltTo32Bytes(priv));
  return {
    version: 'stark-1',
    address: bigIntToHex(derived.address),
    pubKey: bigIntToHex(derived.pubKey),
    accountSalt: bigIntToHex(derived.salt),
    classHash: bigIntToHex(clsBig(classHash)),
    crypto: {
      kdf: 'pbkdf2-sha256',
      iterations,
      salt: hexOf(saltBytes),
      cipher: 'aes-256-gcm',
      iv: hexOf(iv),
      data: hexOf(new Uint8Array(data)),
    },
    createdAt: nowSec,
  };
}

// 上方 encryptToKeystore 需要 classHash 闭包；用小助手保持代码可读
function clsBig(classHash) {
  return typeof classHash === 'bigint' ? classHash : hexToBigInt(classHash);
}

function hexOf(bytes) {
  let out = '0x';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

/** keystore + 口令 → 私钥 felt。错口令/结构非法 fail-closed。 */
export async function decryptFromKeystore(keystore, password) {
  assertCrypto();
  if (!keystore || keystore.version !== 'stark-1' || keystore.crypto?.kdf !== 'pbkdf2-sha256' || keystore.crypto?.cipher !== 'aes-256-gcm') {
    const e = new Error('keystore 结构不受支持');
    e.code = 'BadKeystore';
    throw e;
  }
  if (typeof password !== 'string') {
    const e = new Error('口令错误');
    e.code = 'BadPassword';
    throw e;
  }
  const key = await deriveKey(password, hexToBytes(keystore.crypto.salt), keystore.crypto.iterations);
  let plain;
  try {
    plain = await subtle().decrypt(
      { name: 'AES-GCM', iv: hexToBytes(keystore.crypto.iv) },
      key,
      hexToBytes(keystore.crypto.data),
    );
  } catch {
    const e = new Error('口令错误（AEAD 认证失败）');
    e.code = 'BadPassword';
    throw e;
  }
  const priv = bytes32ToFelt(new Uint8Array(plain));
  // 快路径自检：解密私钥必须能复原 keystore 登记的公钥
  if (keystore.pubKey && privateKeyToPublicKey(priv) !== hexToBigInt(keystore.pubKey)) {
    const e = new Error('keystore 公钥与解密结果不一致（fail-closed）');
    e.code = 'BadKeystore';
    throw e;
  }
  return priv;
}

/** 修改口令：解密 → 新盐/新 IV 重加密。 */
export async function changeKeystorePassword(keystore, currentPassword, nextPassword, {
  iterations = PBKDF2_ITERATIONS, nowSec = Math.floor(Date.now() / 1000),
} = {}) {
  const priv = await decryptFromKeystore(keystore, currentPassword);
  const salt = hexToBigInt(keystore.accountSalt);
  const classHash = hexToBigInt(keystore.classHash);
  const address = hexToBigInt(keystore.address);
  return encryptToKeystore(priv, {
    password: nextPassword, salt, classHash, address, iterations, nowSec,
  });
}

/** 导入私钥解析：hex 字符串（0x 可选），范围 < 2^125 且 > 0。 */
export function parsePrivateKeyHex(hex) {
  if (typeof hex !== 'string') {
    const e = new Error('私钥必须是 hex 字符串');
    e.code = 'InvalidArgument';
    throw e;
  }
  const h = hex.trim().replace(/^0x/, '');
  if (!/^[0-9a-fA-F]{1,64}$/.test(h)) {
    const e = new Error('私钥格式非法');
    e.code = 'InvalidArgument';
    throw e;
  }
  const v = BigInt('0x' + h);
  if (v === 0n || v >= 2n ** 125n) {
    const e = new Error('私钥非法（需 < 2^125）');
    e.code = 'InvalidArgument';
    throw e;
  }
  return v;
}

/** 地址展示（校验和 + 64 位补齐）。 */
export function addressDisplay(address) {
  return toChecksumAddress(address);
}

export { padAddress };
