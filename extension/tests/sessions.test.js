// =============================================================================
// extension/tests/sessions.test.js — SNIP-12 会话密钥授权簿与限额执行测试
// （Extension 0.3/0.4）
//
// 覆盖：
// - 授权草稿（默认 scope = PLAY 低风险集 / withdraw 永不可选 / 限额形状 /
//   单笔 ≤ 每日 / 桌白名单形状 / 有效期上限）；
// - 授权簿（登记形状 fail-closed / 幂等 upsert / 上限 / 撤销粘滞 / 删除）；
// - 状态视图（active/exhausted/revoked/expired/not_yet_valid；跨天窗余量）；
// - **签名路径准入**（与 wallet-core session_admission 同序的 fail-closed
//   镜像：撤销 → 换网 → 时间窗 → scope → 桌白名单 → 单笔限额 → 日限额；
//   每类负例一个独立断言）+ 日限记账（recordSpend 跨天开窗）；
// - governing binding 选择（最新登记优先；撤销粘滞优先于旧 active）。
//
// wallet-core wasm 第二层准入的对应测试在
// `cargo test -p poker-wallet --features wasm --bin wallet_core_wasm`
// （session_check 模块，同一判定顺序的 Rust 单实现）与
// `tests/wasm_smoke.mjs`（wasm 出口真机面）。
// =============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  DEFAULT_SESSION_SCOPES,
  FORBIDDEN_SCOPES,
  SESSION_SCOPES,
  admitOperation,
  bindingStatus,
  bindingView,
  bindingsForOrigin,
  deleteBinding,
  draftAuthorization,
  emptyBindingStore,
  governingBinding,
  operationScope,
  recordSpend,
  revokeBinding,
  upsertBinding,
  validateBindingRecord,
} from '../common/sessions.js';

const NOW = 1_757_000_000; // unix 秒
const DAY = Math.floor(NOW / 86_400);

function binding(overrides = {}) {
  return {
    bindingId: 'ab'.repeat(32),
    origin: 'http://localhost:8080',
    chainId: 'zchain-devnet-1',
    accountAddress: '0x1234',
    delegatedPublicKey: 'cd'.repeat(33),
    allowedScopes: ['play', 'buyin', 'settle'],
    perTxLimit: '1000',
    perDayLimit: '5000',
    tableAllowlist: [1, 2],
    nonce: 7,
    validAfter: NOW - 100,
    validUntil: NOW + 86_400,
    digest: '0x' + 'ef'.repeat(32),
    ...overrides,
  };
}

function seed(store, overrides = {}) {
  const r = upsertBinding(store, binding(overrides));
  assert.equal(r.ok, true, JSON.stringify(r));
  return r.store;
}

// ---------------------------------------------------------------------------
// 1. 授权草稿
// ---------------------------------------------------------------------------

test('01 草稿默认 scope = 低风险集；withdraw 不可选；默认 24h 有效期', () => {
  const d = draftAuthorization({
    origin: 'http://localhost:8080', chainId: 'zchain-devnet-1',
    accountAddress: '0x1234', nowSec: NOW,
  });
  assert.equal(d.ok, true);
  assert.deepEqual(d.request.allowedScopes, DEFAULT_SESSION_SCOPES);
  assert.equal(d.request.validUntil - d.request.validAfter, 24 * 3600);
  assert.equal(d.request.validAfter, NOW);
  assert.ok(Number.isSafeInteger(d.request.nonce));
  // 全集不含 withdraw（禁用类在 FORBIDDEN_SCOPES），草稿永不产出它。
  assert.ok(!SESSION_SCOPES.includes('withdraw'));
  assert.ok(FORBIDDEN_SCOPES.includes('withdraw'));
  assert.ok(!d.request.allowedScopes.includes('withdraw'));
});

test('02 草稿拒绝：withdraw / 未知 scope / 坏限额 / 单笔 > 每日 / 桌白名单形状 / 有效期上限', () => {
  const base = { origin: 'http://x', chainId: 'zchain-devnet-1', accountAddress: '0x1', nowSec: NOW };
  assert.equal(draftAuthorization({ ...base, allowedScopes: ['withdraw'] }).code, 'ScopeForbidden');
  assert.equal(draftAuthorization({ ...base, allowedScopes: ['wizard'] }).code, 'ScopeUnknown');
  assert.equal(draftAuthorization({ ...base, perTxLimit: '0' }).code, 'InvalidArgument');
  assert.equal(draftAuthorization({ ...base, perTxLimit: '-5' }).code, 'InvalidArgument');
  assert.equal(draftAuthorization({ ...base, perDayLimit: '12x' }).code, 'InvalidArgument');
  assert.equal(draftAuthorization({ ...base, perTxLimit: '500', perDayLimit: '100' }).code, 'InvalidArgument');
  assert.equal(draftAuthorization({ ...base, tableAllowlist: '-1,2' }).code, 'InvalidArgument');
  assert.equal(draftAuthorization({ ...base, tableAllowlist: 'a,b' }).code, 'InvalidArgument');
  assert.equal(draftAuthorization({ ...base, validitySec: 366 * 24 * 3600 }).code, 'InvalidArgument');
  assert.equal(draftAuthorization({ ...base, origin: '' }).code, 'InvalidArgument');
  // 正例：桌白名单解析为数组
  const ok = draftAuthorization({ ...base, tableAllowlist: '1, 2' });
  assert.deepEqual(ok.request.tableAllowlist, [1, 2]);
});

test('03 草稿显式 transfer 可勾（非默认但不禁止）；operationScope 映射', () => {
  const d = draftAuthorization({
    origin: 'http://x', chainId: 'zchain-devnet-1', accountAddress: '0x1',
    allowedScopes: ['transfer'], nowSec: NOW,
  });
  assert.equal(d.ok, true);
  assert.deepEqual(d.request.allowedScopes, ['transfer']);
  assert.equal(operationScope('transfer'), 'transfer');
  assert.equal(operationScope('buy_in'), 'buyin');
  assert.equal(operationScope('settle'), 'settle');
  assert.equal(operationScope('withdraw'), null); // 未知 kind 无法准入
  assert.equal(operationScope('bet'), null);      // bet 操作面未开放（fail-closed）
});

// ---------------------------------------------------------------------------
// 2. 授权簿（registry）
// ---------------------------------------------------------------------------

test('04 登记 fail-closed：坏 bindingId / 坏公钥 / 空 scope / 坏限额 / 时间窗倒置', () => {
  assert.equal(validateBindingRecord(binding({ bindingId: 'AB'.repeat(32) })).code, 'InvalidArgument'); // 大写
  assert.equal(validateBindingRecord(binding({ delegatedPublicKey: 'cd'.repeat(32) })).code, 'InvalidArgument');
  assert.equal(validateBindingRecord(binding({ allowedScopes: [] })).code, 'InvalidArgument');
  assert.equal(validateBindingRecord(binding({ allowedScopes: ['withdraw'] })).code, 'InvalidArgument');
  assert.equal(validateBindingRecord(binding({ perTxLimit: '12.5' })).code, 'InvalidArgument');
  assert.equal(validateBindingRecord(binding({ validAfter: 100, validUntil: 100 })).code, 'InvalidArgument');
  assert.equal(validateBindingRecord(binding({ origin: '' })).code, 'InvalidArgument');
  assert.equal(validateBindingRecord(null).code, 'InvalidArgument');
});

test('05 登记幂等 upsert（同 id 替换）+ 上限 + 撤销粘滞 + 删除', () => {
  let store = emptyBindingStore();
  store = seed(store);
  // 同 id upsert：替换为最新（不新增）
  store = seed(store, { perTxLimit: '7' });
  assert.equal(Object.keys(store).length, 1);
  assert.equal(store['ab'.repeat(32)].perTxLimit, '7');
  // 上限
  let full = emptyBindingStore();
  for (let i = 0; i < 16; i++) {
    full = seed(full, { bindingId: (i.toString(16).padStart(2, '0')).repeat(32), origin: `http://h${i}` });
  }
  assert.equal(upsertBinding(full, binding({ bindingId: 'ff'.repeat(32) })).code, 'BindingLimitReached');
  // 撤销粘滞
  const rv = revokeBinding(store, 'ab'.repeat(32), NOW);
  assert.equal(rv.ok, true);
  assert.equal(rv.binding.revoked, true);
  assert.equal(rv.binding.revokedAt, NOW);
  const rv2 = revokeBinding(rv.store, 'ab'.repeat(32), NOW + 5);
  assert.equal(rv2.ok, true);
  assert.equal(rv2.binding.revokedAt, NOW); // 粘滞：时间不回改
  // 未知 binding
  assert.equal(revokeBinding(store, 'ff'.repeat(32)).code, 'UnknownBinding');
  assert.equal(deleteBinding(store, 'ff'.repeat(32)).code, 'UnknownBinding');
  // 删除 = 移除记录
  const del = deleteBinding(store, 'ab'.repeat(32));
  assert.equal(del.ok, true);
  assert.equal(Object.keys(del.store).length, 0);
});

test('06 状态视图：active / not_yet_valid / expired / revoked / exhausted（跨天窗余量）', () => {
  const b = binding({ validAfter: NOW - 100, validUntil: NOW + 100, perDayLimit: '5000' });
  assert.equal(bindingStatus(b, NOW), 'active');
  assert.equal(bindingStatus(binding({ validAfter: NOW + 10, validUntil: NOW + 100 }), NOW), 'not_yet_valid');
  assert.equal(bindingStatus(binding({ validAfter: NOW - 10, validUntil: NOW }), NOW), 'expired');
  assert.equal(bindingStatus(binding({ revoked: true }), NOW), 'revoked');
  // exhausted：同一天窗口内用满
  const ex = binding({ perDayLimit: '5000', dailyUsedDay: DAY, dailyUsedAmount: '5000' });
  assert.equal(bindingStatus(ex, NOW), 'exhausted');
  // 前一天的用量不计入今日
  const ex2 = binding({ perDayLimit: '5000', dailyUsedDay: DAY - 1, dailyUsedAmount: '5000' });
  assert.equal(bindingStatus(ex2, NOW), 'active');
  // 视图投影（脱敏：无密钥材料；余量为字符串；evidence 来自登记来源）
  const v = bindingView(seed(emptyBindingStore(), { dailyUsedDay: DAY, dailyUsedAmount: '5000' })['ab'.repeat(32)], NOW);
  assert.equal(v.status, 'exhausted');
  assert.equal(v.dailyUsedToday, '5000');
  assert.equal(v.evidence, 'devnet_local_entry');
  assert.ok(!('secret' in v) && !('privateKey' in v));
});

// ---------------------------------------------------------------------------
// 3. 签名路径准入（JS 第一层；wallet-core 同序单实现是第二层）
// ---------------------------------------------------------------------------

test('07 准入正例：buyin 在白名单桌、限额内 → ok；金额 BigInt 级不丢精度', () => {
  const b = binding();
  const r = admitOperation(b, { kind: 'buy_in', tableId: 1, amountIn: '1000' }, { chainId: 'zchain-devnet-1', nowSec: NOW });
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.equal(r.scope, 'buyin');
  // u64 级金额（> 2^53）走 BigInt 比较
  const big = admitOperation(
    binding({ perTxLimit: null, perDayLimit: null }),
    { kind: 'buy_in', tableId: 1, amountIn: '9007199254740993' }, // 2^53+1
    { chainId: 'zchain-devnet-1', nowSec: NOW },
  );
  assert.equal(big.ok, true);
});

test('08 准入 fail-closed：每类负例独立断言（与 wallet-core 同序）', () => {
  const ctx = { chainId: 'zchain-devnet-1', nowSec: NOW };
  // (1) 撤销最优先
  assert.equal(admitOperation(binding({ revoked: true }), { kind: 'buy_in', tableId: 1, amountIn: '1' }, ctx).code, 'SessionRevoked');
  // (2) 换网
  assert.equal(admitOperation(binding(), { kind: 'buy_in', tableId: 1, amountIn: '1' }, { ...ctx, chainId: 'zchain-testnet-1' }).code, 'SessionChainMismatch');
  // (3) 时间窗
  assert.equal(admitOperation(binding(), { kind: 'buy_in', tableId: 1, amountIn: '1' }, { ...ctx, nowSec: NOW - 200 }).code, 'SessionNotYetValid');
  assert.equal(admitOperation(binding(), { kind: 'buy_in', tableId: 1, amountIn: '1' }, { ...ctx, nowSec: NOW + 86_400 }).code, 'SessionExpired');
  // (4) scope 不在授权集
  assert.equal(admitOperation(binding(), { kind: 'transfer', amountIn: '1' }, ctx).code, 'SessionScopeNotAllowed');
  // (5) 桌白名单外 / 白名单模式下缺桌 id（fail-closed）
  assert.equal(admitOperation(binding(), { kind: 'buy_in', tableId: 3, amountIn: '1' }, ctx).code, 'SessionTableNotAllowed');
  assert.equal(admitOperation(binding(), { kind: 'settle', amountIn: '1' }, ctx).code, 'SessionTableNotAllowed');
  // 非桌内操作（transfer）不受桌白名单约束
  const okT = admitOperation(binding({ allowedScopes: ['transfer'] }), { kind: 'transfer', amountIn: '1' }, ctx);
  assert.equal(okT.ok, true);
  // (6) 单笔限额
  assert.equal(admitOperation(binding(), { kind: 'buy_in', tableId: 1, amountIn: '1001' }, ctx).code, 'SessionOverPerTxLimit');
  // (7) 日限额（当日累计；恰好用满 = 允许，超过 = 拒——与 wallet-core
  //     `new_total > limit` 判定一致）
  const d = binding({ dailyUsedDay: DAY, dailyUsedAmount: '4200' });
  assert.equal(admitOperation(d, { kind: 'buy_in', tableId: 1, amountIn: '801' }, ctx).code, 'SessionOverDailyLimit');
  const ok = admitOperation(d, { kind: 'buy_in', tableId: 1, amountIn: '800' }, ctx);
  assert.equal(ok.ok, true);
  // 坏金额形状（fail-closed）
  assert.equal(admitOperation(binding(), { kind: 'buy_in', tableId: 1, amountIn: '12.5' }, ctx).code, 'InvalidArgument');
  assert.equal(admitOperation(binding(), { kind: 'buy_in', tableId: 1 }, ctx).code, 'InvalidArgument');
});

test('09 日限记账：跨天自动开窗；BigInt 无精度损失；未知 binding 拒', () => {
  let store = seed(emptyBindingStore(), { dailyUsedDay: DAY, dailyUsedAmount: '4200' });
  const id = 'ab'.repeat(32);
  // 同日累计
  let r = recordSpend(store, id, '800', NOW);
  assert.equal(r.ok, true);
  assert.equal(r.binding.dailyUsedAmount, '5000');
  assert.equal(r.binding.dailyUsedDay, DAY);
  store = r.store;
  // 记满后准入拒绝
  assert.equal(admitOperation(store[id], { kind: 'buy_in', tableId: 1, amountIn: '1' }, { chainId: 'zchain-devnet-1', nowSec: NOW }).code, 'SessionOverDailyLimit');
  // 次日开窗
  const nextDay = NOW + 86_400;
  r = recordSpend(store, id, '5000', nextDay);
  assert.equal(r.binding.dailyUsedDay, Math.floor(nextDay / 86_400));
  assert.equal(r.binding.dailyUsedAmount, '5000');
  // u64 级记账（无精度损失）
  const bigStore = seed(emptyBindingStore(), { perTxLimit: null, perDayLimit: null });
  r = recordSpend(bigStore, id, '18446744073709551615', NOW);
  assert.equal(r.binding.dailyUsedAmount, '18446744073709551615');
  // 坏输入
  assert.equal(recordSpend(store, 'ff'.repeat(32), '1', NOW).code, 'UnknownBinding');
  assert.equal(recordSpend(store, id, '-1', NOW).code, 'InvalidArgument');
});

// ---------------------------------------------------------------------------
// 4. governing binding 选择（执行语义）
// ---------------------------------------------------------------------------

test('10 governing：无 binding → null（常规路径）；仅 expired/not_yet_valid → null', () => {
  const store = emptyBindingStore();
  const ctx = { chainId: 'zchain-devnet-1', nowSec: NOW };
  assert.equal(governingBinding(store, 'http://localhost:8080', ctx.chainId, NOW), null);
  // 自然过期 → 授权不再适用
  const expired = seed(emptyBindingStore(), { validAfter: NOW - 2000, validUntil: NOW - 1000 });
  assert.equal(governingBinding(expired, 'http://localhost:8080', ctx.chainId, NOW), null);
  // 未生效 → 不适用
  const future = seed(emptyBindingStore(), { validAfter: NOW + 1000, validUntil: NOW + 2000 });
  assert.equal(governingBinding(future, 'http://localhost:8080', ctx.chainId, NOW), null);
});

test('11 governing：最新登记优先；撤销最新 → 拒；重授权后新 binding 管辖', () => {
  const ctx = { chainId: 'zchain-devnet-1', nowSec: NOW };
  const id1 = 'ab'.repeat(32);
  const id2 = 'cd'.repeat(32);
  // 两个 active binding → 最新（registeredAt 更大）管辖
  let store = seed(emptyBindingStore(), { registeredAt: 1000 });
  store = seed(store, { bindingId: id2, origin: 'http://localhost:8080', registeredAt: 2000, perTxLimit: '5' });
  let g = governingBinding(store, 'http://localhost:8080', ctx.chainId, NOW);
  assert.equal(g.bindingId, id2);
  // 撤销最新 → 签名拒绝（撤销粘滞优先于旧 active）
  store = revokeBinding(store, id2, NOW).store;
  g = governingBinding(store, 'http://localhost:8080', ctx.chainId, NOW);
  assert.equal(g.bindingId, id2);
  assert.equal(g.revoked, true);
  assert.equal(admitOperation(g, { kind: 'buy_in', tableId: 1, amountIn: '1' }, ctx).code, 'SessionRevoked');
  // 删除被撤销记录 → 回落到旧 binding（仍是 active → 管辖）
  store = deleteBinding(store, id2).store;
  g = governingBinding(store, 'http://localhost:8080', ctx.chainId, NOW);
  assert.equal(g.bindingId, id1);
  // 换网后的 binding 不影响当前网（chain 隔离）
  const testnetOnly = seed(emptyBindingStore(), { chainId: 'zchain-testnet-1' });
  assert.equal(governingBinding(testnetOnly, 'http://localhost:8080', ctx.chainId, NOW), null);
  // origin 隔离
  const otherOrigin = seed(emptyBindingStore(), { origin: 'http://other' });
  assert.equal(governingBinding(otherOrigin, 'http://localhost:8080', ctx.chainId, NOW), null);
  assert.equal(bindingsForOrigin(otherOrigin, 'http://localhost:8080', 'zchain-devnet-1').length, 0);
});
