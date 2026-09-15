// 快速向量自检（正式断言在 tests/evm/crypto.test.js）
import {
  keccak256, bytesToHex, privateToPublicKey, addressFromPublicKey, toChecksumAddress,
  signLegacyTransaction, parseAndRecoverTransaction, ecSign, ecVerify, ecRecover,
  rlpEncode, hexToBytes,
} from '../../common/evm/crypto.js';

const eq = (name, a, b) => {
  const ok = a === b;
  console.log(`${ok ? 'PASS' : 'FAIL'}: ${name}${ok ? '' : `\n  got:    ${a}\n  expect: ${b}`}`);
  if (!ok) process.exitCode = 1;
};

// keccak256 标准向量
eq('keccak("")', bytesToHex(keccak256(new Uint8Array(0))),
  '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
eq('keccak("abc")', bytesToHex(keccak256(new TextEncoder().encode('abc'))),
  '0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45');

// G 点 / 地址推导已知向量（priv=1, priv=2）
const pub1 = privateToPublicKey(1n);
eq('priv=1 pub x', bytesToHex(pub1.subarray(1, 33)),
  '0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
eq('priv=1 address', addressFromPublicKey(pub1), '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf');
const pub2 = privateToPublicKey(2n);
eq('priv=2 address', addressFromPublicKey(pub2), '0x2b5ad5c4795c026514f8317c7a215e218dccd6cf');

// EIP-55 校验和（EIP-55 规范示例）
eq('eip55 a', toChecksumAddress('0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed'),
  '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed');
eq('eip55 b', toChecksumAddress('0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359'),
  '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359');
eq('eip55 c', toChecksumAddress('0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb'),
  '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB');
eq('eip55 d', toChecksumAddress('0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb'),
  '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb');

// EIP-155 规范示例交易：私钥 0x46…46 / chainId 1
// （规范给定的 r/s 由随机 k 产生，不与确定性 k 逐字节相等；锚点是：
//  ① 规范给定的 signing data 编码 + keccak == 规范给定的签名哈希；
//  ② 我方签名可被解析恢复出与规范私钥一致的 sender；v=37 结构一致。）
const priv = '0x4646464646464646464646464646464646464646464646464646464646464646';
const eip155Unsigned = [
  hexToBytes('0x09'), hexToBytes('0x04a817c800'), hexToBytes('0x5208'),
  hexToBytes('0x3535353535353535353535353535353535353535'), hexToBytes('0x0de0b6b3a7640000'),
  new Uint8Array(0), hexToBytes('0x01'), new Uint8Array(0), new Uint8Array(0),
];
eq('eip155 signing hash', bytesToHex(keccak256(rlpEncode(eip155Unsigned))),
  '0xdaf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53');
const signed = signLegacyTransaction({
  nonce: 9, gasPrice: '20000000000', gasLimit: 21000,
  to: '0x3535353535353535353535353535353535353535', value: '1000000000000000000',
  data: '0x', chainId: 1,
}, priv);
const parsedSpec = parseAndRecoverTransaction(
  '0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83');
const expectedFrom = toChecksumAddress(addressFromPublicKey(privateToPublicKey(priv)));
eq('eip155 spec tx recover sender', parsedSpec.from, expectedFrom);
const parsed = parseAndRecoverTransaction(signed.raw);
eq('eip155 our tx recover sender', parsed.from, expectedFrom);
eq('eip155 our tx v', signed.v.toString(), '37');
eq('eip155 recover hash', parsed.hash, signed.hash);

// 签名 → 验证 → 恢复 自洽（随机 key，多 digest）
for (let i = 0; i < 3; i++) {
  const sk = new Uint8Array(32).fill(i + 1);
  const digest = bytesToHex(keccak256(new TextEncoder().encode(`msg-${i}`)));
  const sig = ecSign(digest, sk);
  const pub = privateToPublicKey(sk);
  if (!ecVerify(digest, sig.r, sig.s, pub)) { console.log(`FAIL: verify ${i}`); process.exitCode = 1; }
  const recPub = ecRecover(digest, sig.r, sig.s, sig.recovery);
  eq(`recover pubkey ${i}`, bytesToHex(recPub), bytesToHex(pub));
}
console.log('scratch done');
