// =============================================================================
// extension/tests/accounts.test.js — 多账户账本纯逻辑测试（Extension 0.2）
//
// 覆盖：创建（上限/去重/坏 id/标签清洗/默认网络）/ 选中隔离（账户元数据
// 互不影响）/ 移除 / 授权簿与网络按账户隔离 / 0.1 单账户无损迁移。
// =============================================================================

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  MAX_ACCOUNTS,
  activeAccount,
  createAccount,
  emptyLedger,
  migrateLegacySingle,
  removeAccount,
  selectAccount,
  setAccountGrants,
  setAccountNetwork,
  sanitizeLabel,
} from '../common/accounts.js';

const NOW = 1_757_000_000_000;
const KS = { version: 1, owner_envelope: 'aa', dek_envelope: 'bb', play_store: 'cc', real_store: 'dd' };

function seedLedger(n = 1) {
  let ledger = emptyLedger();
  for (let i = 0; i < n; i++) {
    const r = createAccount(ledger, {
      id: `acct-${i}-aaaaaaaaaaaaaaaa`,
      keystore: KS,
      publicKey: 'ab'.repeat(33),
      label: `账户${i}`,
      now: NOW + i,
    });
    assert.equal(r.ok, true, r.reason);
    ledger = r.ledger;
  }
  return ledger;
}

test('01 创建账户：默认 devnet；新建即选中；keystore 密文原样保存', () => {
  const r = createAccount(emptyLedger(), { id: 'acct-a-aaaaaaaaaaaaaaaa', keystore: KS, publicKey: 'ab'.repeat(33), now: NOW });
  assert.equal(r.ok, true);
  assert.equal(r.ledger.activeAccountId, 'acct-a-aaaaaaaaaaaaaaaa');
  assert.equal(r.account.networkId, 'zchain-devnet-1');
  assert.equal(r.account.keystore, KS);
  assert.deepEqual(activeAccount(r.ledger).grants, {});
});

test('02 创建拒绝：重复 id / 坏 id / 坏账本 / 缺 keystore / 未登记网络', () => {
  const ledger = seedLedger(1);
  assert.equal(createAccount(ledger, { id: 'acct-0-aaaaaaaaaaaaaaaa', keystore: KS, now: NOW }).code, 'DuplicateAccount');
  assert.equal(createAccount(ledger, { id: 'x', keystore: KS, now: NOW }).code, 'InvalidArgument');
  assert.equal(createAccount(ledger, { id: 'acct-b-aaaaaaaaaaaaaaaa', keystore: null, now: NOW }).code, 'InvalidArgument');
  assert.equal(createAccount(ledger, { id: 'acct-b-aaaaaaaaaaaaaaaa', keystore: KS, networkId: 'zchain-mainnet-1', now: NOW }).code, 'NetworkUnsupported');
  assert.equal(createAccount(null, { id: 'acct-b-aaaaaaaaaaaaaaaa', keystore: KS, now: NOW }).code, 'InvalidArgument');
});

test('03 账户数上限（MAX_ACCOUNTS）拒绝再创建', () => {
  let ledger = emptyLedger();
  for (let i = 0; i < MAX_ACCOUNTS; i++) {
    const r = createAccount(ledger, { id: `acct-${i}-aaaaaaaaaaaaaaaa`, keystore: KS, now: NOW + i });
    assert.equal(r.ok, true);
    ledger = r.ledger;
  }
  const over = createAccount(ledger, { id: 'acct-over-aaaaaaaaaaaaaa', keystore: KS, now: NOW });
  assert.equal(over.code, 'AccountLimitReached');
});

test('04 切换隔离：切换只推进 activeAccountId 与目标的 lastSelectedAt，其余零变化', () => {
  const ledger = seedLedger(2);
  const before = JSON.parse(JSON.stringify(ledger.accounts['acct-0-aaaaaaaaaaaaaaaa']));
  const r = selectAccount(ledger, 'acct-0-aaaaaaaaaaaaaaaa', NOW + 100);
  assert.equal(r.ok, true);
  assert.equal(r.ledger.activeAccountId, 'acct-0-aaaaaaaaaaaaaaaa');
  // 被选中的账户 0 只有 lastSelectedAt 推进，其余字段（含密文/授权簿）不变。
  const after = { ...r.ledger.accounts['acct-0-aaaaaaaaaaaaaaaa'], lastSelectedAt: before.lastSelectedAt };
  assert.deepEqual(after, before);
  assert.equal(r.ledger.accounts['acct-0-aaaaaaaaaaaaaaaa'].lastSelectedAt, NOW + 100);
  // 账户 1 完全不被触碰。
  assert.deepEqual(r.ledger.accounts['acct-1-aaaaaaaaaaaaaaaa'], ledger.accounts['acct-1-aaaaaaaaaaaaaaaa']);
  // 未知账户
  assert.equal(selectAccount(ledger, 'nope', NOW).code, 'UnknownAccount');
});

test('05 授权簿/网络按账户隔离（§6.12.4 账户元数据隔离）', () => {
  const ledger = seedLedger(2);
  const g = setAccountGrants(ledger, 'acct-0-aaaaaaaaaaaaaaaa', { 'https://play.example': { grantedAt: NOW } });
  assert.equal(g.ok, true);
  // 账户 0 有授权，账户 1 无。
  assert.deepEqual(g.ledger.accounts['acct-0-aaaaaaaaaaaaaaaa'].grants, { 'https://play.example': { grantedAt: NOW } });
  assert.deepEqual(g.ledger.accounts['acct-1-aaaaaaaaaaaaaaaa'].grants, {});
  // 网络：账户 1 切到 testnet，账户 0 仍 devnet。
  const n = setAccountNetwork(g.ledger, 'acct-1-aaaaaaaaaaaaaaaa', 'zchain-testnet-1', NOW);
  assert.equal(n.ok, true);
  assert.equal(n.ledger.accounts['acct-1-aaaaaaaaaaaaaaaa'].networkId, 'zchain-testnet-1');
  assert.equal(n.ledger.accounts['acct-0-aaaaaaaaaaaaaaaa'].networkId, 'zchain-devnet-1');
  // 未登记网络拒绝
  assert.equal(setAccountNetwork(n.ledger, 'acct-1-aaaaaaaaaaaaaaaa', 'zchain-mainnet-1', NOW).code, 'NetworkUnsupported');
  // 授权/网络对未知账户拒绝
  assert.equal(setAccountGrants(ledger, 'nope', {}).code, 'UnknownAccount');
  assert.equal(setAccountNetwork(ledger, 'nope', 'zchain-devnet-1', NOW).code, 'UnknownAccount');
});

test('06 移除账户：密文与授权簿一并消失；移除当前选中则 activeAccountId 清空', () => {
  const ledger = seedLedger(2); // active = acct-1
  const r = removeAccount(ledger, 'acct-1-aaaaaaaaaaaaaaaa');
  assert.equal(r.ok, true);
  assert.equal(r.ledger.accounts['acct-1-aaaaaaaaaaaaaaaa'], undefined);
  assert.equal(r.ledger.activeAccountId, null); // 移除的是当前选中 → 清空
  // 非当前选中被移除时，active 保持不变。
  const sel = selectAccount(r.ledger, 'acct-0-aaaaaaaaaaaaaaaa', NOW + 1);
  const r2 = removeAccount(sel.ledger, 'nonexistent-aaaaaaaaaaa');
  assert.equal(r2.ok, false); // 不存在的账户不能移除
  const other = seedLedger(2);
  const sel2 = selectAccount(other, 'acct-0-aaaaaaaaaaaaaaaa', NOW + 1);
  const r3 = removeAccount(sel2.ledger, 'acct-1-aaaaaaaaaaaaaaaa');
  assert.equal(r3.ok, true);
  assert.equal(r3.ledger.activeAccountId, 'acct-0-aaaaaaaaaaaaaaaa');
  assert.equal(removeAccount(ledger, 'nope-aaaaaaaaaaaaaaaa').code, 'UnknownAccount');
});

test('07 0.1 单账户无损迁移：keystore 密文 + 全局授权簿归入首账户', () => {
  const legacy = {
    keystore: KS,
    grants: { 'https://play.example': { grantedAt: 1 } },
    publicKey: 'cd'.repeat(33),
  };
  const m = migrateLegacySingle(emptyLedger(), legacy, NOW);
  assert.equal(m.migrated, true);
  const acct = activeAccount(m.ledger);
  assert.equal(acct.keystore, KS);
  assert.deepEqual(acct.grants, legacy.grants);
  assert.equal(acct.publicKey, 'cd'.repeat(33));
  assert.equal(acct.networkId, 'zchain-devnet-1'); // 0.1 只有 devnet
  // 有账本/无 keystore 时不迁移
  assert.equal(migrateLegacySingle(seedLedger(1), legacy, NOW).migrated, false);
  assert.equal(migrateLegacySingle(emptyLedger(), null, NOW).migrated, false);
});

test('08 标签清洗：控制字符剥离、截断、空标签回落默认编号', () => {
  assert.equal(sanitizeLabel('  我的桌  '), '我的桌');
  assert.equal(sanitizeLabel('a\u0000b'), 'ab');
  assert.equal(sanitizeLabel('x'.repeat(100)), 'x'.repeat(64));
  assert.equal(sanitizeLabel(''), null);
  assert.equal(sanitizeLabel(42), null);
});
