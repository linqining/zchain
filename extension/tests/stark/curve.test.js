// =============================================================================
// tests/stark/curve.test.js — STARK curve 密码学标准向量测试（Extension 0.6）
// 向量来源：
//   - 公钥推导 / ECDSA 验证正负例：StarkWare crypto-cpp（经 starknet-crypto
//     0.8.1 测试套件逐字移植）
//   - Pedersen：StarkEx signature_test_data.json 官方向量
//   - 交易哈希：starknet.js v6.11.0 transactionHash.test.ts 官方向量
//   - 地址推导 / 校验和地址：与 starknet.js v6.11.0 官方实现对拍
//     （calculateContractAddressFromHash 源码 docstring 旧算例已过时，
//      以 npm 官方包运行结果为准）
//   - 选择器：'__validate__'（starknet.js 官方测试）、'transfer'（生态通用）
// =============================================================================
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  bytesToHex, keccak256, hexToBytes,
} from '../../common/evm/crypto.js';
import {
  FIELD_P, EC_ORDER_N, FELT_BOUND, ADDR_BOUND, GENERATOR,
  privateKeyToPublicKey, ecSign, ecVerify, ecRecover, generatePrivateKey,
  pedersenHash, computeHashOnElements, starknetKeccak, starknetSelector,
  calculateContractAddress, calculateInvokeTransactionHash,
  toChecksumAddress, padAddress, isAddress, isOnCurve,
  encodeShortString, decodeShortString, u256ToFeltPair, feltPairToU256,
  hexToBigInt, toFelt, modSqrt, modInverse,
  _internals,
} from '../../common/stark/curve.js';

test('曲线参数自洽：G 在曲线上、n 阶点乘回零域、域常数', () => {
  assert.ok(isOnCurve(GENERATOR.x, GENERATOR.y));
  assert.equal(FIELD_P, 2n ** 251n + 17n * 2n ** 192n + 1n);
  assert.equal(ADDR_BOUND, 2n ** 251n - 256n);
  // n·G = 无穷远（点乘后 y 与 -y 重合/jacToAffine null）
  const inf = _internals.jacMul(EC_ORDER_N, [GENERATOR.x, GENERATOR.y, 1n]);
  assert.equal(inf[2], 0n);
});

test('公钥推导：StarkWare crypto-cpp 官方向量', () => {
  assert.equal(privateKeyToPublicKey(0x12n).toString(16),
    '19661066e96a8b9f06a1d136881ee924dfb6a885239caa5fd3f87a54c6b25c4');
  assert.equal(privateKeyToPublicKey('0x03c1e9550e66958296d11b60f8e8e7a7ad990d07fa65d5f7652c4a6c87d4e3cc').toString(16),
    '77a3b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43');
  assert.throws(() => privateKeyToPublicKey(0n));
  assert.throws(() => privateKeyToPublicKey(EC_ORDER_N));
});

test('ECDSA 验证：crypto-cpp 官方正例 + 负例 + 拒绝面', () => {
  assert.equal(ecVerify(
    '0x01ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca',
    '0x02',
    '0x0411494b501a98abd8262b0da1351e17899a0c4ef23dd2f96fec5ba847310b20',
    '0x0405c3191ab3883ef2b763af35bc5f5d15b3b4e99461d70e84c654a351a7c81b'), true);
  assert.equal(ecVerify(
    '0x077a4b314db07c45076d11f62b6f9e748a39790441823307743cf00d6597ea43',
    '0x0397e76d1667c4454bfb83514e120583af836f8e32a516765497823eabe16a3f',
    '0x0173fd03d8b008ee7432977ac27d1e9d1a1f6c98b1a2f05fa84a21c84c44e882',
    '0x01f2c44a7798f55192f153b4c48ea5c1241fbb69e6132cc8a0da9c5b62a4286e'), false);
  // 坏公钥（不在曲线上）→ false，不抛
  assert.equal(ecVerify('0x03ee9bffffffffff26ffffffff60ffffffffffffffffffffffffffff004accff',
    '0x02', '0x1', '0x1'), false);
  // 非法消息哈希（≥ 2^251）拒绝
  assert.throws(() => ecSign(FELT_BOUND, 1n), /felt range/);
});

test('ECDSA 签名/恢复：确定性 k + 验证 + recover 往返（随机密钥）', () => {
  for (let i = 0; i < 5; i++) {
    const priv = generatePrivateKey();
    const pubX = privateKeyToPublicKey(priv);
    const z = BigInt(i * 7919 + 1); // 任意 felt
    const sig = ecSign(z, priv);
    assert.ok(sig.r > 0n && sig.r < EC_ORDER_N);
    assert.ok(sig.s > 0n && sig.s < EC_ORDER_N);
    // 确定性
    const again = ecSign(z, priv);
    assert.equal(sig.r, again.r);
    assert.equal(sig.s, again.s);
    // 验证
    assert.equal(ecVerify(pubX, z, sig.r, sig.s), true);
    // 篡改 digest → 验证失败
    assert.equal(ecVerify(pubX, z + 1n, sig.r, sig.s), false);
    // 恢复（两个 v 至少一个命中公钥）
    const r0 = _recoverTry(z, sig, pubX, 0);
    const r1 = _recoverTry(z, sig, pubX, 1);
    assert.ok(r0 || r1);
  }
});

function _recoverTry(z, sig, pubX, v) {
  try {
    return ecRecover(z, sig.r, sig.s, v) === pubX;
  } catch {
    return false;
  }
}

test('Pedersen：StarkEx signature_test_data 官方向量 + 零元性质', () => {
  assert.equal(padAddress(pedersenHash(
    '0x03d937c035c878245caf64531a5756109c53068da139362728feb561405371cb',
    '0x0208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a')),
  '0x030e480bed5fe53fa909cc0f8c4d99b8f9f2c016be4c41e13a4848797979c662');
  assert.equal(padAddress(pedersenHash(
    '0x058f580910a6ca59b28927c08fe6c43e2e303ca384badc365795fc645d479d45',
    '0x078734f65a067be9bdb39de18434d71e79f7b6466a4b66bbd979ab9e7515fe0b')),
  '0x068cc0b76cddd1dd4ed2301ada9b7c872b23875d5ff837b3a87993e0d9996b87');
  // H(0,0) = shift_point.x（starknet-crypto oracle 确认）
  assert.equal(padAddress(pedersenHash(0n, 0n)),
    '0x049ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804');
});

test('元素哈希/交易哈希：starknet.js 官方向量（SN_SEPOLIA 6 元素）', () => {
  const SN_SEPOLIA = encodeShortString('SN_SEPOLIA');
  const INVOKE = encodeShortString('invoke');
  // calculateTransactionHashCommon(INVOKE, '0x0', '0x2a', '0x64', [], '0x0', SN_SEPOLIA)
  assert.equal(computeHashOnElements([INVOKE, 0n, 0x2an, 0x64n, computeHashOnElements([]), 0n, SN_SEPOLIA]).toString(16),
    '63ba2bc7f3a3912597e221d5fad8eb0783e0684a428b47fa4737faf66f46dfb');
  // invoke v1 组装函数（8 元素形态）：同链路一致性冒烟
  const h = calculateInvokeTransactionHash({
    version: 1n, senderAddress: '0x2a', calldata: [0x1n, 0x2n], maxFee: 5n,
    chainId: SN_SEPOLIA, nonce: 7n,
  });
  assert.equal(h, computeHashOnElements([
    INVOKE, 1n, 0x2an, 0n, computeHashOnElements([1n, 2n]), 5n, SN_SEPOLIA, 7n,
  ]));
});

test('地址推导：与 starknet.js v6.11.0 官方实现对拍 + 边界', () => {
  assert.equal(padAddress(calculateContractAddress({
    salt: 1234n,
    classHash: '0x1cf4fe5d37868d25524cdacb89518d88bf217a9240a1e6fde71cc22c429e0e3',
    constructorCalldata: [1234n, 1n, 0n],
    deployerAddress: '0x052fb1a9ab0db3c4f81d70fea6a2f6e55f57c709a46089b25eeec0e959db3695',
  })), '0x051e39cc7419e60285d34f29f0e045b8eea1da0ccd7d1c16f255867120508f56');
  // 空构造参数 + deployer 0
  const a = calculateContractAddress({ salt: 1n, classHash: 0x1234n, constructorCalldata: [] });
  assert.ok(a >= 0n && a < ADDR_BOUND);
  // felt 值域越界拒绝（2^251）；ADDR_BOUND + 1 仍是合法 felt（地址 < 2^251 − 256 但 felt 域更大）
  assert.throws(() => calculateContractAddress({ salt: FELT_BOUND, classHash: 1n }), /felt range/);
  assert.ok(calculateContractAddress({ salt: ADDR_BOUND + 1n, classHash: 1n }) < ADDR_BOUND);
});

test('选择器：starknet_keccak（mod 2^250）', () => {
  assert.equal(starknetSelector('__validate__').toString(16),
    '162da33a4585851fe8d3af3c2a9c60b557814e221e0d4f30ff0b2189d9c7775');
  assert.equal(starknetSelector('transfer').toString(16),
    '83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e');
  // starknet.js 官方测试向量
  assert.equal(starknetSelector('myFunction').toString(16),
    'c14cfe23f3fa7ce7b1f8db7d7682305b1692293f71a61cc06637f0d8d8b6c8');
  // starknetKeccak < 2^250
  assert.ok(starknetKeccak(new Uint8Array(32).fill(0xff)) < 2n ** 250n);
  // keccak 一致性（与 @noble/hashes 独立实现对拍，2026-09-16 实测一致）
  assert.equal(bytesToHex(keccak256(hexToBytes('0x0abc'))),
    '0xe91cf08aac85935e32397f410e48217a127b6855d41b1e3877eb4179c0904b77');
});

test('校验和地址：starknet.js 官方向量 + 幂等 + 解析', () => {
  const v = toChecksumAddress('0x2fd23d9182193775423497fc0c472e156c57c69e4089a1967fb288a2d84e914');
  assert.equal(v, '0x02Fd23d9182193775423497fc0c472E156C57C69E4089A1967fb288A2d84e914');
  assert.equal(toChecksumAddress(v), v);
  assert.ok(isAddress('0x49d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7'));
  assert.ok(!isAddress('0xzz'));
  assert.throws(() => toFelt('0x' + 'f'.repeat(64)), /felt range/);
});

test('短字符串与 u256：编解码往返', () => {
  assert.equal(decodeShortString(encodeShortString('SN_MAIN')), 'SN_MAIN');
  assert.equal(encodeShortString('invoke').toString(16), '696e766f6b65');
  assert.throws(() => encodeShortString('a'.repeat(32)), /too long/);
  const v = 123456789012345678901234567890n;
  const [lo, hi] = u256ToFeltPair(v);
  assert.equal(feltPairToU256(lo, hi), v);
  assert.deepEqual(u256ToFeltPair(0n), [0n, 0n]);
  assert.throws(() => u256ToFeltPair(2n ** 256n), /u256 overflow/);
});

test('域运算：modSqrt / modInverse 边界', () => {
  // 平方根正确性：任一平方元素的 sqrt 平方回自身
  for (const base of [1n, 4n, 9n, GENERATOR.y]) {
    const sq = (base * base) % FIELD_P;
    const r = modSqrt(sq);
    assert.ok(r !== null && (r * r) % FIELD_P === sq);
  }
  const neg1 = modSqrt(FIELD_P - 1n);
  assert.ok(neg1 !== null && (neg1 * neg1) % FIELD_P === FIELD_P - 1n); // p ≡ 1 (mod 4) → -1 是二次剩余
  assert.equal(modInverse(2n, EC_ORDER_N) * 2n % EC_ORDER_N, 1n);
});

test('generatePrivateKey：grindKey 语义 ∈ [1, 2^251)', () => {
  for (let i = 0; i < 20; i++) {
    const k = generatePrivateKey();
    assert.ok(k > 0n && k < 2n ** 251n);
    assert.ok(k < EC_ORDER_N);
  }
  // 高位密钥（≥ 2^125，旧上限之上）全链路可用：公钥推导 + 签名/验证
  const hi = 2n ** 250n;
  const pubX = privateKeyToPublicKey(hi);
  const sig = ecSign(123n, hi);
  assert.equal(ecVerify(pubX, 123n, sig.r, sig.s), true);
});
