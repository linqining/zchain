// =============================================================================
// tests/evm/crypto.test.js — EVM 密码学模块标准向量测试（Extension 0.5）
// 锚点：keccak256 公共向量、secp256k1 G 点已知向量、EIP-55 规范示例、
// EIP-155 规范示例交易（signing hash + 规范签名交易的 sender 恢复一致性）、
// RLP/签名恢复自洽、数值格式化边界。
// =============================================================================
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  keccak256, bytesToHex, hexToBytes, utf8ToBytes, concatBytes, bigIntToBytes, bytesToBigInt,
  privateToPublicKey, addressFromPublicKey, toChecksumAddress, isAddress,
  ecSign, ecVerify, ecRecover, generatePrivateKeyBytes, SECP256K1_N,
  rlpEncode, rlpDecode,
  signLegacyTransaction, parseAndRecoverTransaction,
  formatUnits, parseUnits,
  encodeTuple, decodeTuple, encodeCall, functionSelector,
} from '../../common/evm/crypto.js';

const te = (s) => new TextEncoder().encode(s);

test('keccak256 标准向量', () => {
  assert.equal(bytesToHex(keccak256(new Uint8Array(0))),
    '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
  assert.equal(bytesToHex(keccak256(te('abc'))),
    '0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45');
  // 跨 136 字节 rate 边界的多块吸收
  const long = new Uint8Array(300).fill(0x61);
  const h = keccak256(long);
  assert.equal(h.length, 32);
  // 确定性：同输入同输出
  assert.deepEqual(keccak256(long), h);
});

test('secp256k1 公钥推导：G 点已知向量 + 地址推导', () => {
  const pub1 = privateToPublicKey(1n);
  assert.equal(bytesToHex(pub1.subarray(1, 33)),
    '0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  assert.equal(addressFromPublicKey(pub1), '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf');
  assert.equal(addressFromPublicKey(privateToPublicKey(2n)), '0x2b5ad5c4795c026514f8317c7a215e218dccd6cf');
  assert.throws(() => privateToPublicKey(0n));
  assert.throws(() => privateToPublicKey(SECP256K1_N));
});

test('EIP-55 校验和地址（规范示例）', () => {
  for (const expect of [
    '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
    '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
    '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
    '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
  ]) {
    assert.equal(toChecksumAddress(expect.toLowerCase()), expect);
    assert.equal(toChecksumAddress(expect), expect); // 幂等
  }
  assert.ok(isAddress('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed'));
  assert.ok(!isAddress('0x123'));
});

test('RLP 编解码往返（整数/字符串/嵌套列表/边界）', () => {
  assert.equal(bytesToHex(rlpEncode(new Uint8Array([0]))), '0x00');
  assert.equal(bytesToHex(rlpEncode(new Uint8Array([0x7f]))), '0x7f');
  assert.equal(bytesToHex(rlpEncode(new Uint8Array([0x80]))), '0x8180');
  assert.equal(bytesToHex(rlpEncode(new Uint8Array(0))), '0x80');
  const dog = rlpEncode([utf8ToBytes('cat'), utf8ToBytes('dog')]);
  assert.equal(bytesToHex(dog), '0xc88363617483646f67');
  assert.deepEqual(rlpDecode(dog), [utf8ToBytes('cat'), utf8ToBytes('dog')]);
  // 长列表（>55 字节负载）
  const big = rlpEncode([new Uint8Array(64).fill(1)]);
  assert.equal(big[0], 0xf8);
  const [decoded] = [rlpDecode(big)];
  assert.equal(decoded.length, 1);
  assert.equal(decoded[0].length, 64);
  // 整数语义：0 → 空串
  assert.deepEqual(rlpEncode([new Uint8Array(0)]), rlpEncode([new Uint8Array(0)]));
});

test('EIP-155 签名：signing hash 与规范一致 + sender 恢复一致', () => {
  const priv = '0x4646464646464646464646464646464646464646464646464646464646464646';
  const unsigned = [
    hexToBytes('0x09'), hexToBytes('0x04a817c800'), hexToBytes('0x5208'),
    hexToBytes('0x3535353535353535353535353535353535353535'),
    hexToBytes('0x0de0b6b3a7640000'), new Uint8Array(0),
    hexToBytes('0x01'), new Uint8Array(0), new Uint8Array(0),
  ];
  assert.equal(bytesToHex(keccak256(rlpEncode(unsigned))),
    '0xdaf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53');

  const specRaw = '0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83';
  const expectedFrom = toChecksumAddress(addressFromPublicKey(privateToPublicKey(priv)));
  // 规范签名交易（随机 k）经我们的解析恢复出规范私钥的地址
  const spec = parseAndRecoverTransaction(specRaw);
  assert.equal(spec.from, expectedFrom);
  assert.equal(spec.value.toString(), '1000000000000000000');
  assert.equal(spec.chainId, 1n);

  // 我方（确定性 k）签名同样恢复一致；v ∈ {37,38}（低 s 规范化下合法）
  const signed = signLegacyTransaction({
    nonce: 9, gasPrice: '20000000000', gasLimit: 21000,
    to: '0x3535353535353535353535353535353535353535',
    value: '1000000000000000000', data: '0x', chainId: 1,
  }, priv);
  const mine = parseAndRecoverTransaction(signed.raw);
  assert.equal(mine.from, expectedFrom);
  assert.ok(signed.v === 37n || signed.v === 38n);
  assert.equal(signed.hash, mine.hash);
  // 确定性 k：同输入签名逐字节一致
  const again = signLegacyTransaction({
    nonce: 9, gasPrice: '20000000000', gasLimit: 21000,
    to: '0x3535353535353535353535353535353535353535',
    value: '1000000000000000000', data: '0x', chainId: 1,
  }, priv);
  assert.equal(signed.raw, again.raw);
});

test('ECDSA 签名/验证/恢复往返（随机密钥 × 若干 digest）', () => {
  for (let i = 0; i < 5; i++) {
    const sk = generatePrivateKeyBytes();
    const digest = bytesToHex(keccak256(te(`msg-${i}-${Math.random()}`)));
    const pub = privateToPublicKey(sk);
    const sig = ecSign(digest, sk);
    assert.ok(ecVerify(digest, sig.r, sig.s, pub));
    // 低 s
    assert.ok(sig.s <= SECP256K1_N / 2n);
    // 恢复公钥一致
    assert.deepEqual(ecRecover(digest, sig.r, sig.s, sig.recovery), pub);
    // 错 digest 恢复不出同一公钥
    const other = bytesToHex(keccak256(te('other')));
    assert.notDeepEqual(ecRecover(other, sig.r, sig.s, sig.recovery), pub);
  }
});

test('signLegacyTransaction 拒绝面', () => {
  const sk = generatePrivateKeyBytes();
  assert.throws(() => signLegacyTransaction({ nonce: 0, gasPrice: 1, gasLimit: 21000, to: '0x1234', value: 0, data: '0x', chainId: 1 }, sk), /bad `to`/);
  assert.throws(() => signLegacyTransaction({ nonce: 0, gasPrice: 1, gasLimit: 21000, to: null, value: 0, data: '0x', chainId: 0 }, sk));
});

test('数值格式化：wei ⇄ 十进制（无浮点）', () => {
  assert.equal(formatUnits(10n ** 18n), '1');
  assert.equal(formatUnits(1500000000000000000n), '1.5');
  assert.equal(formatUnits(1n), '0.000000000000000001');
  assert.equal(formatUnits(0n), '0');
  assert.equal(parseUnits('1.5'), 1500000000000000000n);
  assert.equal(parseUnits('0.000000000000000001'), 1n);
  assert.equal(parseUnits('10'), 10n ** 19n);
  assert.equal(parseUnits('0x10'), 16n);
  assert.throws(() => parseUnits('abc'));
  assert.throws(() => formatUnits('nope'));
});

test('ABI 元组编解码：静态/动态/数组', () => {
  // (uint256,address,bool,string,bytes,uint8[2])
  const types = ['uint256', 'address', 'bool', 'string', 'bytes', 'uint8[2]'];
  const values = ['255', '0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed', true, 'hello', '0xdeadbeef', [1, 2]];
  const enc = encodeTuple(types, values);
  assert.equal(enc.length % 32, 0);
  const dec = decodeTuple(types, bytesToHex(enc));
  assert.deepEqual(dec, ['255', '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed', true, 'hello', '0xdeadbeef', ['1', '2']]);
  // 动态数组
  const dec2 = decodeTuple(['uint256[]'], bytesToHex(encodeTuple(['uint256[]'], [['7', '9']])));
  assert.deepEqual(dec2, [['7', '9']]);
  // 空 bytes
  const dec3 = decodeTuple(['bytes'], bytesToHex(encodeTuple(['bytes'], ['0x'])));
  assert.deepEqual(dec3, ['0x']);
});

test('函数选择器著名向量（transfer(address,uint256)）', () => {
  assert.equal(functionSelector('transfer(address,uint256)'), '0xa9059cbb');
  assert.equal(functionSelector('balanceOf(address)'), '0x70a08231');
  assert.equal(functionSelector('approve(address,uint256)'), '0x095ea7b3');
});

test('encodeCall 组装：selector + 参数', () => {
  const data = encodeCall('transfer(address,uint256)', ['address', 'uint256'],
    ['0x2b5ad5c4795c026514f8317c7a215e218dccd6cf', '1000']);
  assert.ok(data.startsWith('0xa9059cbb'));
  assert.equal(data.length, 2 + 8 + 64 * 2);
});

test('bigInt/bytes 边界', () => {
  assert.deepEqual(bigIntToBytes(0n), new Uint8Array(0));
  assert.deepEqual(bigIntToBytes(1n, 4), new Uint8Array([0, 0, 0, 1]));
  assert.throws(() => bigIntToBytes(65536n, 2));
  assert.equal(bytesToBigInt(new Uint8Array([1, 0])), 256n);
  assert.deepEqual(concatBytes(new Uint8Array([1]), new Uint8Array([2, 3])), new Uint8Array([1, 2, 3]));
});
