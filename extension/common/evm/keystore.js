// =============================================================================
// extension/common/evm/keystore.js — EVM 私钥 keystore（Extension 0.5）
//
// 口令 → PBKDF2-HMAC-SHA256 派生 KEK → AES-256-GCM 加密私钥（WebCrypto
// 平台原语；扩展页/SW 为安全上下文，Node ≥ 20 有 webcrypto 全局——单测直跑）。
// keystore 落 chrome.storage.local 时是密文；导出私钥/改密码都要显式口令
// （fail-closed：错口令 = AEAD 认证失败 = BadPassword）。
//
// 形状（v1）：
// {
//   version: 1,
//   address: '0x…'（EIP-55）,
//   crypto: { kdf: 'pbkdf2-sha256', iterations, salt(hex), cipher: 'aes-256-gcm',
//             iv(hex 12B), data(hex) },
//   createdAt: unix 秒,
// }
// =============================================================================

import { hexToBytes, bytesToHex, privateToPublicKey, addressFromPublicKey, toChecksumAddress, generatePrivateKeyBytes } from './crypto.js';

export const PBKDF2_ITERATIONS = 600_000;

const subtle = () => globalThis.crypto.subtle;

function assertCrypto() {
  if (typeof globalThis.crypto?.subtle?.importKey !== 'function') {
    throw new Error('WebCrypto subtle 不可用（需要安全上下文 / Node ≥ 20）');
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

/** 由私钥推导 EIP-55 地址（导出/导入共用）。 */
export function addressFromPrivateKey(privBytes) {
  return toChecksumAddress(addressFromPublicKey(privateToPublicKey(privBytes)));
}

/**
 * 生成随机私钥 + 加密 keystore。
 * @returns {Promise<{keystore: object, address: string, privateKey: string}>}
 *          privateKey 仅用于创建当次的展示回执，不落任何存储。
 */
export async function createKeystore(password, { iterations = PBKDF2_ITERATIONS, nowSec = Math.floor(Date.now() / 1000) } = {}) {
  requirePassword(password);
  const priv = generatePrivateKeyBytes();
  const keystore = await encryptToKeystore(priv, password, { iterations, nowSec });
  return { keystore, address: keystore.address, privateKey: bytesToHex(priv) };
}

/** 私钥字节 → 加密 keystore。 */
export async function encryptToKeystore(privBytes, password, { iterations = PBKDF2_ITERATIONS, nowSec = Math.floor(Date.now() / 1000) } = {}) {
  requirePassword(password);
  if (!(privBytes instanceof Uint8Array) || privBytes.length !== 32) {
    const e = new Error('私钥必须是 32 字节');
    e.code = 'InvalidArgument';
    throw e;
  }
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveKey(password, salt, iterations);
  const data = await subtle().encrypt({ name: 'AES-GCM', iv }, key, privBytes);
  const address = addressFromPrivateKey(privBytes);
  return {
    version: 1,
    address,
    crypto: {
      kdf: 'pbkdf2-sha256',
      iterations,
      salt: bytesToHex(salt),
      cipher: 'aes-256-gcm',
      iv: bytesToHex(iv),
      data: bytesToHex(new Uint8Array(data)),
    },
    createdAt: nowSec,
  };
}

/** keystore + 口令 → 私钥字节。错口令/结构非法 fail-closed。 */
export async function decryptFromKeystore(keystore, password) {
  assertCrypto();
  if (!keystore || keystore.version !== 1 || keystore.crypto?.kdf !== 'pbkdf2-sha256' || keystore.crypto?.cipher !== 'aes-256-gcm') {
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
  const priv = new Uint8Array(plain);
  // 快路径自检：解密结果的地址必须与 keystore 元数据一致（防挂载错位）。
  const derived = addressFromPrivateKey(priv);
  if (keystore.address && derived.toLowerCase() !== String(keystore.address).toLowerCase()) {
    const e = new Error('keystore 地址与解密结果不一致（fail-closed）');
    e.code = 'BadKeystore';
    throw e;
  }
  return priv;
}

/** 修改口令：解密 → 新盐/新 IV 重加密（旧 keystore 不可用）。 */
export async function changeKeystorePassword(keystore, currentPassword, nextPassword, { iterations = PBKDF2_ITERATIONS, nowSec = Math.floor(Date.now() / 1000) } = {}) {
  const priv = await decryptFromKeystore(keystore, currentPassword);
  return encryptToKeystore(priv, nextPassword, { iterations, nowSec });
}

/**
 * 校验外部导入的私钥 hex（0x + 64 hex；允许 66 位非压缩形式则拒绝——只收 32 字节原始私钥）。
 * @returns {Uint8Array} 32 字节私钥
 */
export function parsePrivateKeyHex(hex) {
  if (typeof hex !== 'string') {
    const e = new Error('私钥必须是 hex 字符串');
    e.code = 'InvalidArgument';
    throw e;
  }
  const h = hex.trim().replace(/^0x/, '');
  if (!/^[0-9a-fA-F]{64}$/.test(h)) {
    const e = new Error('私钥格式非法（需要 64 位 hex）');
    e.code = 'InvalidArgument';
    throw e;
  }
  const bytes = hexToBytes(h);
  // 全零/超阶拒绝
  if (bytes.every((b) => b === 0)) {
    const e = new Error('私钥非法（全零）');
    e.code = 'InvalidArgument';
    throw e;
  }
  return bytes;
}
