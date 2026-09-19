// =============================================================================
// extension/common/transfer_preview.js — 钱包侧 PLAY 转账选币（方向 B「贪心选币」）
//
// 设计出处：design/zchain-wallet-ui-b-ledger.html 的 `转账 · 贪心选币` 屏——
// 支出 note 列表、找零 note、凭证阶梯短板、可提交判定全部在同一张预览里给出。
//
// 与 REAL 提现预览（common/withdraw_preview.js）的分工：
// - 提现是**展示态**：canSubmit 恒 false（REAL 签名面未开放，红线不动）；
// - 转账是**可提交态**：GAME 域 PLAY 是本版本唯一可签资产类，预览产出的
//   operation 就是送去 wallet-core 的那一份——UI 展示的摘要与签名摘要同源。
//
// 账本约束（决定选币形状，全部来自 wallet-core 的签名面语义）：
// 1. note 全额消费：不存在"部分花费一张 note"，因此 Σoutputs 必须等于
//    Σinputs（守恒）；不足找零就要多一条回本账户的 output；
// 2. inputs ≤ LIMITS.maxInputs（批量签名防护）；
// 3. GAME 域凭证门槛：支出 note 的 proof 短板必须 ≥ proven（低于则 fail-closed
//    禁提交，与 REAL 的 finalized 门槛分列，不混用）。
//
// 纯函数、零 IO、零密码学（摘要与签名只在 wallet-core）。
// =============================================================================

import { LIMITS, U64_MAX, validateAmount, validateHex } from './validation.js';
import { PROOF_LADDER } from './ui_ledger.js';

/** GAME 域支出 note 的最低凭证层级（低于此不可签出）。 */
export const GAME_MIN_PROOF = 'proven';

/**
 * devnet 放宽层：本地水龙头铸的 stub note 在 wallet-core 里是
 * `ProofState::Soft`（没有批次根，无法诚实声称 proven），而 devnet 的 PLAY
 * 又只是无价值测试筹码。门槛是**网络策略**而不是 UI 口径：devnet 放宽到
 * soft，testnet/mainnet 维持设计要求 proven（那里才有真正的 prover 输出）。
 */
export const DEVNET_MIN_PROOF = 'soft';

/** 按网络形态取 GAME 域支出门槛。 */
export function minProofForNetwork(kind) {
  return kind === 'devnet' ? DEVNET_MIN_PROOF : GAME_MIN_PROOF;
}

/** 找零输出的 label（UI 展示口径）。 */
export const CHANGE_NOTE_LABEL = '找零 note';

/** 用户输入归一：允许千分位/下划线与 `.00` 形式的整数，其余一律拒绝（不四舍五入）。 */
export function parseAmountInput(raw) {
  const s = String(raw ?? '').trim().replace(/[,\s_]/g, '');
  if (s === '') return { ok: false, code: 'AmountInvalid', reason: '请输入金额' };
  const m = /^(\d+)(?:\.(\d+))?$/.exec(s);
  if (!m) return { ok: false, code: 'AmountInvalid', reason: '金额必须是十进制数字' };
  if (m[2] != null && !/^0+$/.test(m[2])) {
    return { ok: false, code: 'AmountInvalid', reason: 'PLAY 为整数筹码，不支持小数' };
  }
  const int = m[1].replace(/^0+(?=\d)/, '');
  return validateAmount(int);
}

/**
 * 贪心选币：按金额降序取 note 直到覆盖目标（note 全额消费）。
 * @returns {{selected:Array, totalIn:bigint, covered:boolean}}
 */
export function selectNotes(notes, amount) {
  const target = BigInt(amount);
  const spendable = (Array.isArray(notes) ? notes : []).filter((n) => n && n.spendable !== false);
  const sorted = [...spendable].sort((a, b) => {
    const x = BigInt(a.amount ?? '0');
    const y = BigInt(b.amount ?? '0');
    if (y > x) return 1;
    if (y < x) return -1;
    return String(a.commitment ?? '').localeCompare(String(b.commitment ?? ''));
  });
  const selected = [];
  let totalIn = 0n;
  for (const n of sorted) {
    if (totalIn >= target) break;
    selected.push(n);
    totalIn += BigInt(n.amount ?? '0');
  }
  return { selected, totalIn, covered: totalIn >= target };
}

/** proof 层级短比较（未知层级按 pending 处理，从严）。 */
function rankOf(proof) {
  const i = PROOF_LADDER.indexOf(proof);
  return i < 0 ? 0 : i;
}

/**
 * 构造钱包侧 PLAY 转账预览（含可直接送进 wallet-core 的 operation）。
 *
 * @param {object} input
 *   amount        用户输入（十进制字符串，允许千分位）
 *   owner         收款 owner（hex33 压缩公钥，无 0x）
 *   selfOwner     本账户 owner（找零去向；缺省则无法找零 → 禁提交）
 *   playNotes     脱敏 PLAY note：[{commitment, amount, proof, spendable}]
 *   chainId       当前网络链 ID
 *   nowSec        当前 unix 秒（可注入以便测试确定性）
 *   nonce         签名 nonce（缺省 = nowSec*1000，与页面侧 Date.now() 同口径）
 *   ttlSec        有效期（缺省 300s）
 *   minProof      凭证门槛（缺省 GAME_MIN_PROOF）
 * @returns {{ok:true, preview}} | {{ok:false, code, reason}}
 */
export function buildTransferPreview(input = {}) {
  const amt = parseAmountInput(input.amount);
  if (!amt.ok) return { ok: false, code: amt.code, reason: amt.reason };
  const amount = amt.amount;

  const ownerRes = validateHex(input.owner, 33, { maxLen: 132 });
  if (!ownerRes.ok) {
    return { ok: false, code: 'OwnerInvalid', reason: '收款 owner 必须是 66 位 hex（33B 压缩公钥，不带 0x）' };
  }
  const owner = String(input.owner).toLowerCase();
  // 全零 owner = 无效曲线点（收款即烧毁）：fail-closed 拒绝，不给 wallet-core
  // 留"签出一笔注定不可用资产"的口子。
  if (/^0+$/.test(owner)) {
    return { ok: false, code: 'OwnerInvalid', reason: '收款 owner 不能为全零（无效公钥）' };
  }
  const selfRaw = typeof input.selfOwner === 'string' ? input.selfOwner.trim() : '';
  const selfOk = selfRaw.length > 0 && validateHex(selfRaw, 33, { maxLen: 132 }).ok;
  const selfOwner = selfOk ? selfRaw.toLowerCase() : null;

  if (owner === selfOwner) {
    return { ok: false, code: 'SelfTransfer', reason: '收款 owner 与本账户相同（自转无意义）' };
  }

  const nowSec = Number.isSafeInteger(input.nowSec) ? input.nowSec : Math.floor(Date.now() / 1000);
  const ttlSec = Number.isSafeInteger(input.ttlSec) && input.ttlSec > 0 ? input.ttlSec : 300;
  const nonce = Number.isSafeInteger(input.nonce) ? input.nonce : nowSec * 1000;
  const minProof = PROOF_LADDER.includes(input.minProof) ? input.minProof : GAME_MIN_PROOF;

  const { selected, totalIn, covered } = selectNotes(input.playNotes, amount);
  const change = totalIn - BigInt(amount);
  const worst = selected.reduce(
    (acc, n) => (rankOf(n.proof) < rankOf(acc) ? (PROOF_LADDER.includes(n.proof) ? n.proof : 'pending') : acc),
    selected.length > 0 ? 'finalized' : 'none',
  );
  const finalityReached = selected.length > 0 && covered && rankOf(worst) >= rankOf(minProof);

  const reasons = [];
  const spendableTotal = (Array.isArray(input.playNotes) ? input.playNotes : [])
    .filter((n) => n && n.spendable !== false)
    .reduce((acc, n) => acc + BigInt(n.amount ?? '0'), 0n);

  if (selected.length === 0) {
    reasons.push('没有可花费的 PLAY note（devnet 水龙头铸造测试筹码）');
  } else if (!covered) {
    reasons.push(`可花费余额不足：需要 ${amount}，可用 ${spendableTotal.toString()}`);
  } else if (selected.length > LIMITS.maxInputs) {
    reasons.push(`选币数量 ${selected.length} 超出批量上限 ${LIMITS.maxInputs}`);
  }
  if (covered && change > 0n && !selfOwner) {
    reasons.push(`需要找零 ${change.toString()}，但本账户 owner 未知（找零无处可去）`);
  }
  if (selected.length > 0 && covered && !finalityReached) {
    reasons.push(`凭证短板为 ${worst}，GAME 域要求 ≥ ${minProof}`);
  }
  if (totalIn > U64_MAX) reasons.push('合计金额超出 u64 范围');

  const outputs = [{ owner, amount }];
  if (covered && change > 0n && selfOwner) {
    outputs.push({ owner: selfOwner, amount: change.toString(), change: true });
  }
  const conservationOk = covered && outputs.reduce((a, o) => a + BigInt(o.amount), 0n) === totalIn;
  if (!conservationOk && covered) reasons.push('选币结果不守恒（内部一致性检查失败）');

  const canSubmit = reasons.length === 0 && covered && conservationOk;

  const operation = {
    kind: 'transfer',
    assetClass: 'PLAY',
    chainId: typeof input.chainId === 'string' ? input.chainId : null,
    domain: 'zchain',
    abiVersion: 1,
    nonce,
    expiry: nowSec + ttlSec,
    inputs: selected.map((n) => n.commitment).filter((c) => typeof c === 'string'),
    outputs: outputs.map((o) => ({ owner: o.owner, amount: o.amount })),
  };

  return {
    ok: true,
    preview: {
      kind: 'transfer',
      assetClass: 'PLAY',
      domain: 'GAME',
      chainId: operation.chainId,
      amount,
      owner,
      selfOwner,
      inputs: selected.map((n) => ({
        commitment: n.commitment ?? null,
        amount: String(n.amount ?? '0'),
        proof: PROOF_LADDER.includes(n.proof) ? n.proof : 'pending',
        spendable: n.spendable !== false,
      })),
      totalIn: totalIn.toString(),
      change: change > 0n ? change.toString() : '0',
      outputs,
      finality: {
        worstProof: worst,
        requiredProof: minProof,
        reached: finalityReached,
      },
      covered,
      spendableTotal: spendableTotal.toString(),
      canSubmit,
      cannotSubmitReasons: reasons,
      fee: { paidBy: 'gateway', amount: '0', label: '网关代付' },
      generatedAtSec: nowSec,
      operation,
    },
  };
}

/** 提现预览的同源门槛常量（展示用；REAL 侧另有 finalized 要求）。 */
export const REAL_MIN_PROOF = 'finalized';

/**
 * 签名前的凭证复核（后台边界用，不依赖 UI 那份预览结论）：
 * operation.inputs 里的每张 note 必须**存在、可花费、且 proof 不低于门槛**。
 * 这是"UI 说可提交 ≠ 可以签"的第二道闸：预览与签名之间note 状态可能已变
 * （被消费、层级回退），也可能有人绕过 UI 直接发 RPC。
 *
 * @returns {{ok:true, worst} | {ok:false, code, reason, worst}}
 */
export function verifySpendProofs({ playNotes, inputs, minProof = GAME_MIN_PROOF } = {}) {
  const byCommitment = new Map();
  for (const n of (Array.isArray(playNotes) ? playNotes : [])) {
    if (n && typeof n.commitment === 'string') byCommitment.set(n.commitment.toLowerCase(), n);
  }
  const list = Array.isArray(inputs) ? inputs : [];
  if (list.length === 0) return { ok: false, code: 'NoSpendableNote', reason: '待签 operation 没有输入 note', worst: 'none' };
  let worst = 'finalized';
  for (const c of list) {
    const n = byCommitment.get(String(c ?? '').toLowerCase());
    if (!n) {
      return { ok: false, code: 'NoteNotFound', reason: `输入 note ${String(c).slice(0, 12)}… 不在本账户库中`, worst: 'none' };
    }
    if (n.spendable === false) {
      return { ok: false, code: 'NoteNotSpendable', reason: `输入 note ${String(c).slice(0, 12)}… 已被锁定/消费`, worst: 'none' };
    }
    const p = PROOF_LADDER.includes(n.proof) ? n.proof : 'pending';
    if (rankOf(p) < rankOf(worst)) worst = p;
  }
  if (rankOf(worst) < rankOf(minProof)) {
    return { ok: false, code: 'ProofBelowGate', reason: `凭证短板 ${worst} 低于 GAME 域门槛 ${minProof}`, worst };
  }
  return { ok: true, worst };
}
