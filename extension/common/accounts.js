// =============================================================================
// extension/common/accounts.js — 多账户账本纯逻辑（Extension 0.2）
//
// §6.12.4 "每个 origin 的权限、网络和账户选择单独保存"在 0.2 的落地：
// 每个账户 = { 元数据 + keystore 密文 + origin 授权簿 + 网络选择 }，物理上
// 各自独立保存；锁定/切换当前账户只影响当前会话（其他账户本来就是密文，
// 不共享任何解锁态）。
//
// 纯函数、零依赖、无 IO：存储由调用方（background service worker）持有，
// 本模块返回"下一状态"。零密码学（keystore 全部是 wallet-core 信封密文）。
// =============================================================================

import { DEFAULT_NETWORK_ID, resolveNetwork } from './networks.js';

/** 账户 id 形状校验（内部不透明标识：uuid 或 legacy 前缀；仅用于索引，
 *  不参与密码学）。字符集/长度有界，防止把 id 当成注入面。 */
export function isValidAccountId(id) {
  return typeof id === 'string' && /^[A-Za-z0-9_-]{8,64}$/.test(id);
}

/** 账户标签上限（防资源滥用；标签是展示字段，非密）。 */
export const MAX_LABEL_LENGTH = 64;
/** 单钱包账户数上限（本地 keystore 数量防护）。 */
export const MAX_ACCOUNTS = 8;

/**
 * 空账本。
 * @returns {{accounts: Object, activeAccountId: string|null}}
 */
export function emptyLedger() {
  return { accounts: {}, activeAccountId: null };
}

/**
 * 新建账户记录（keystore 由调用方以 wallet-core 密文信封给出）。
 *
 * @param ledger   当前账本
 * @param opts     {id, label?, keystore, publicKey, networkId?, now}
 * @returns {ok:true, ledger, account} | {ok:false, code, reason}
 */
export function createAccount(ledger, opts) {
  const { id, keystore, publicKey, now, label, networkId } = opts ?? {};
  if (!isValidAccountId(id)) return { ok: false, code: 'InvalidArgument', reason: 'bad account id' };
  if (!ledger || typeof ledger !== 'object' || !ledger.accounts) {
    return { ok: false, code: 'InvalidArgument', reason: 'bad ledger' };
  }
  if (ledger.accounts[id]) return { ok: false, code: 'DuplicateAccount', reason: id };
  if (Object.keys(ledger.accounts).length >= MAX_ACCOUNTS) {
    return { ok: false, code: 'AccountLimitReached', reason: `max ${MAX_ACCOUNTS} accounts` };
  }
  if (keystore == null || typeof keystore !== 'object') {
    return { ok: false, code: 'InvalidArgument', reason: 'keystore ciphertext envelope required' };
  }
  const net = resolveNetwork(networkId ?? DEFAULT_NETWORK_ID);
  if (!net) return { ok: false, code: 'NetworkUnsupported', reason: String(networkId) };
  const account = {
    id,
    label: sanitizeLabel(label) ?? `账户 ${Object.keys(ledger.accounts).length + 1}`,
    createdAt: now,
    lastSelectedAt: now,
    publicKey: typeof publicKey === 'string' ? publicKey : null,
    networkId: net.chainId,
    // origin 授权簿：**每账户独立**（§6.12.4 账户隔离语义）。
    grants: {},
    // keystore 密文（wallet-core 信封：owner/dek envelope + 双库快照）。
    keystore,
  };
  return {
    ok: true,
    ledger: {
      accounts: { ...ledger.accounts, [id]: account },
      activeAccountId: id, // 新建即选中
    },
    account,
  };
}

/**
 * 选中账户（切换）：只推进 activeAccountId 与 lastSelectedAt；**不触碰**
 * 任何其他账户记录（锁定语义由会话层保证——切换即锁当前会话，目标账户
 * 需要口令解锁，与源账户无关）。
 */
export function selectAccount(ledger, accountId, now) {
  if (!ledger?.accounts?.[accountId]) {
    return { ok: false, code: 'UnknownAccount', reason: String(accountId) };
  }
  const accounts = { ...ledger.accounts };
  accounts[accountId] = { ...accounts[accountId], lastSelectedAt: now };
  return { ok: true, ledger: { accounts, activeAccountId: accountId } };
}

/** 移除账户（其密文与授权簿一并消失；不影响其他账户）。 */
export function removeAccount(ledger, accountId) {
  if (!ledger?.accounts?.[accountId]) {
    return { ok: false, code: 'UnknownAccount', reason: String(accountId) };
  }
  const accounts = { ...ledger.accounts };
  delete accounts[accountId];
  const activeAccountId =
    ledger.activeAccountId === accountId ? null : ledger.activeAccountId;
  return { ok: true, ledger: { accounts, activeAccountId } };
}

/** 更新账户的 origin 授权簿（返回新账本；账户间不可见）。 */
export function setAccountGrants(ledger, accountId, grants) {
  const account = ledger?.accounts?.[accountId];
  if (!account) return { ok: false, code: 'UnknownAccount', reason: String(accountId) };
  return {
    ok: true,
    ledger: {
      ...ledger,
      accounts: {
        ...ledger.accounts,
        [accountId]: { ...account, grants: grants ?? {} },
      },
    },
  };
}

/** 更新账户网络选择（未登记网络拒绝）。 */
export function setAccountNetwork(ledger, accountId, chainId, now) {
  const account = ledger?.accounts?.[accountId];
  if (!account) return { ok: false, code: 'UnknownAccount', reason: String(accountId) };
  const net = resolveNetwork(chainId);
  if (!net) return { ok: false, code: 'NetworkUnsupported', reason: String(chainId) };
  return {
    ok: true,
    ledger: {
      ...ledger,
      accounts: {
        ...ledger.accounts,
        [accountId]: { ...account, networkId: net.chainId, networkChangedAt: now },
      },
    },
  };
}

/** 当前选中账户（无 → null）。 */
export function activeAccount(ledger) {
  if (!ledger?.activeAccountId) return null;
  return ledger.accounts[ledger.activeAccountId] ?? null;
}

/** 授权簿迁移（0.1 单账户 → 0.2 账本）：legacy `keystore`/`grants` 存在且
 *  账本为空时迁入首个账户（keystore 密文原样搬运，origin 授权簿归入该账户）。 */
export function migrateLegacySingle(ledger, legacy, now) {
  if (!ledger || Object.keys(ledger.accounts ?? {}).length > 0) return { migrated: false, ledger };
  if (legacy?.keystore == null) return { migrated: false, ledger };
  const id = legacy.accountId ?? `legacy-${now.toString(36)}`;
  const created = createAccount(ledger, {
    id,
    keystore: legacy.keystore,
    publicKey: legacy.publicKey ?? null,
    networkId: legacy.chainId ?? DEFAULT_NETWORK_ID,
    label: '默认账户（0.1 迁移）',
    now,
  });
  if (!created.ok) return { migrated: false, ledger };
  // 迁移 origin 授权簿到该账户名下。
  const withGrants = setAccountGrants(created.ledger, id, legacy.grants ?? {});
  if (!withGrants.ok) return { migrated: false, ledger: created.ledger };
  return { migrated: true, ledger: withGrants.ledger };
}

/** 标签清洗（可打印、有界；标签非敏感但也不该成为注入面）。 */
export function sanitizeLabel(label) {
  if (typeof label !== 'string') return null;
  const trimmed = label.trim();
  if (trimmed.length === 0) return null;
  // 控制字符一律剥离。
  const clean = [...trimmed].filter((ch) => ch.charCodeAt(0) >= 32).join('');
  return clean.slice(0, MAX_LABEL_LENGTH) || null;
}
