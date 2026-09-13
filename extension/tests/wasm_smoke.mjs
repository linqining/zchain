// wallet-core WASM 冒烟测试（真实密码学路径，非 mock）。
//
// 前置：poker-wallet 已按 src/wasm.rs 模块文档完成 wasm 构建 + wasm-bindgen 绑定，
// 产物在 extension/vendor/wallet-core/。缺产物时跳过（构建命令见 extension/README.md）。
//
// 运行：node extension/tests/wasm_smoke.mjs
//
// 验证链路：create(Argon2id+ChaCha20-Poly1305+secp256k1) → faucet PLAY note →
// preview → sign（digest/borsh ABI）→ persist/lock/unlock（错口令 fail-closed）→
// nonce 重放拒绝。全部密码学发生在 wallet-core wasm 内，本文件零密码学实现。

import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const VENDOR = join(HERE, "..", "vendor", "wallet-core");
const WASM_PATH = join(VENDOR, "wallet_core_wasm_bg.wasm");
const GLUE_PATH = join(VENDOR, "wallet_core_wasm.js");

const NOW = "1757000000";
const EXP = "1757003600";
const CHAIN = "zchain-devnet-1";

test("wallet-core wasm: real keystore + signer path", { skip: !existsSync(WASM_PATH) }, async () => {
  const glue = await import("file://" + GLUE_PATH);
  const bytes = new Uint8Array(readFileSync(WASM_PATH));
  await glue.default(bytes); // default = __wbg_init（wasm-bindgen --target web）

  // 0. 元信息
  const meta = JSON.parse(glue.wallet_core_meta());
  assert.equal(meta.domain, "zchain");
  assert.equal(meta.abi_version, 1);
  assert.equal(meta.default_chain_id, CHAIN);

  // 1. 创建钱包（真实 Argon2id 信封 + secp256k1 owner key）
  const created = JSON.parse(glue.wallet_create("correct horse battery staple", "test"));
  assert.ok(!created.error, `create failed: ${created.detail}`);
  const pubKey = created.public_key;
  assert.equal(pubKey.length, 66); // 33B hex

  // 2. devnet PLAY 水龙头（本地 stub）×2 → 500
  const f1 = JSON.parse(glue.wallet_faucet_play("300"));
  assert.ok(!f1.error, `faucet failed: ${f1.detail}`);
  const f2 = JSON.parse(glue.wallet_faucet_play("200"));
  assert.equal(f2.play_free, "500");

  // 3. 预览（不占用 nonce）
  const req = {
    kind: "transfer",
    chain_id: CHAIN,
    domain: "zchain",
    abi_version: 1,
    nonce: "1",
    expiry: EXP,
    asset_class: "PLAY",
    inputs: [f1.commitment, f2.commitment],
    outputs: [{ owner: pubKey, amount: "500" }],
  };
  const prev = JSON.parse(glue.wallet_preview(JSON.stringify(req), NOW));
  assert.ok(!prev.error, `preview failed: ${prev.detail}`);
  assert.equal(prev.preview.amount_in, "500");
  assert.equal(prev.preview.asset_class, "PLAY");
  assert.ok(prev.preview.digest.length === 64);

  // 4. 签名（真实 secp256k1 + blake2s 摘要 + borsh ABI，全在 wasm 内）
  const signed = JSON.parse(glue.wallet_sign(JSON.stringify(req), NOW));
  assert.ok(!signed.error, `sign failed: ${signed.detail}`);
  assert.equal(signed.digest, prev.preview.digest); // 预览与签名摘要一致
  assert.ok(signed.operation_borsh.length > 0);

  // 5. nonce 重放拒绝（同一 (chain, nonce) 二次签名）
  const replay = JSON.parse(glue.wallet_sign(JSON.stringify(req), NOW));
  assert.equal(replay.error, "NonceReplay", `expected NonceReplay, got ${JSON.stringify(replay)}`);

  // 6. ABI 版本不认识拒绝
  const badAbi = JSON.parse(
    glue.wallet_sign(JSON.stringify({ ...req, nonce: "2", abi_version: 2 }), NOW),
  );
  assert.equal(badAbi.error, "UnknownAbiVersion");

  // 7. 持久化 → 锁定 → 正确口令解锁（note 状态保留）
  const ks = JSON.parse(glue.wallet_persist());
  assert.equal(glue.wallet_lock(), JSON.stringify({ locked: true }));
  const unlocked = JSON.parse(glue.wallet_unlock(JSON.stringify(ks), "correct horse battery staple"));
  assert.ok(!unlocked.error, `unlock failed: ${unlocked.detail}`);
  assert.equal(unlocked.public_key, pubKey);
  assert.equal(unlocked.notes, 2); // 花费标记保留在库内

  // 8. 错误口令 fail-closed
  glue.wallet_lock();
  const bad = JSON.parse(glue.wallet_unlock(JSON.stringify(ks), "wrong password"));
  assert.equal(bad.error, "BadPassword");

  // 8b. 恢复解锁态（后续 0.2 步骤需要会话）
  const relocked = JSON.parse(glue.wallet_unlock(JSON.stringify(ks), "correct horse battery staple"));
  assert.ok(!relocked.error, `re-unlock failed: ${relocked.detail}`);

  // 9. 脱敏：note 列表不含 spend secret / nullifier / 私钥
  const notes = JSON.parse(glue.wallet_get_notes());
  const blob = JSON.stringify(notes);
  assert.ok(!blob.includes("spend_secret"));
  assert.ok(!blob.includes("nullifier"));
  assert.ok(blob.length < 4096);

  // ===== Extension 0.2 入口 =====

  // 10. REAL/PLAY 分库视图（wallet_get_all_notes）：PLAY 有 note，REAL 空；
  //     余额按资产类分栏；脱敏纪律同 9。
  const all = JSON.parse(glue.wallet_get_all_notes());
  assert.ok(!all.error, `get_all_notes failed: ${all.detail}`);
  assert.equal(all.play.length, 2);
  assert.equal(all.real.length, 0);
  assert.equal(all.balances.play_free, "500");
  assert.equal(all.balances.real_free, "0");
  const allBlob = JSON.stringify(all);
  assert.ok(!allBlob.includes("spend_secret") && !allBlob.includes("nullifier"));

  // 11. 展示门（wallet_display_views，display.rs 单实现）：REAL claim 恒隐藏
  //     + 托管风险提示常显（0.2 readiness 恒 offline）；PLAY 视图无 REAL 字段。
  const views = JSON.parse(glue.wallet_display_views());
  assert.ok(!views.error, `display_views failed: ${views.detail}`);
  assert.equal(views.real.show_claim, false);
  assert.equal(views.real.claim_disabled_reason, "vault_offline");
  assert.ok(views.real.custody_risk_notice?.startsWith("real_is_custodial"));
  assert.ok(!JSON.stringify(views.play).toLowerCase().includes("real"));

  // 12. 结算关系复验（wallet_verify_settlement_detail）：结构非法 fail-closed
  //     （正例路径由 portal E2E 用真实 explorer gateway 明细覆盖）。
  const badBinding = JSON.parse(
    glue.wallet_verify_settlement_detail(JSON.stringify({ ...detailLike(), hand_binding: "00".repeat(32) })),
  );
  assert.equal(badBinding.error, "InvalidArgument");
  const badOwner = JSON.parse(
    glue.wallet_verify_settlement_detail(JSON.stringify(detailLike({ payouts: [{ owner: "zz", amount: 1, asset_class: "PLAY", pot_index: 0, runout_index: 0 }] }))),
  );
  assert.equal(badOwner.error, "InvalidArgument");

  // 13. 备份导出（ZCBK v1）→ 错口令 / 篡改字节 fail-closed → 正确口令恢复
  const exported = JSON.parse(glue.wallet_backup_export("backup pass phrase 1", "test", NOW));
  assert.ok(!exported.error, `backup export failed: ${exported.detail}`);
  assert.ok(exported.backup_hex.length > 0);
  assert.equal(exported.notes.play, 2);
  assert.equal(exported.notes.real, 0);
  const backupBytes = new Uint8Array(exported.backup_hex.length / 2);
  for (let i = 0; i < backupBytes.length; i++) backupBytes[i] = parseInt(exported.backup_hex.slice(i * 2, i * 2 + 2), 16);

  // 13a. 错误口令 → BadPassword（AEAD 认证失败）
  const badPw = JSON.parse(glue.wallet_backup_import(exported.backup_hex, "wrong pass phrase"));
  assert.equal(badPw.error, "BadPassword");

  // 13b. 篡改一个密文字节 → 拒绝（fail-closed）
  const tampered = new Uint8Array(backupBytes);
  tampered[tampered.length - 1] ^= 0x01;
  const tamperedHex = Array.from(tampered, (b) => b.toString(16).padStart(2, "0")).join("");
  const tamperedRes = JSON.parse(glue.wallet_backup_import(tamperedHex, "backup pass phrase 1"));
  assert.ok(tamperedRes.error === "BadPassword" || tamperedRes.error === "Tampered", `expected tamper rejection, got ${tamperedRes.error}`);

  // 13c. 正确口令：keystore 信封 + 双库快照 + public_key 一致
  const restored = JSON.parse(glue.wallet_backup_import(exported.backup_hex, "backup pass phrase 1"));
  assert.ok(!restored.error, `backup import failed: ${restored.detail}`);
  assert.equal(restored.public_key, pubKey);
  assert.equal(restored.keystore.play_store.length, ks.play_store.length);
  assert.equal(restored.keystore.real_store.length, ks.real_store.length);
  assert.equal(restored.indexes.commitments, 2);
  assert.equal(restored.indexes.nullifiers, 2);

  // 13d. 用恢复出的 keystore + 备份口令解锁 → 同一账户
  glue.wallet_lock();
  const unlockedRestored = JSON.parse(glue.wallet_unlock(JSON.stringify(restored.keystore), "backup pass phrase 1"));
  assert.ok(!unlockedRestored.error, `restored unlock failed: ${unlockedRestored.detail}`);
  assert.equal(unlockedRestored.public_key, pubKey);
  assert.equal(unlockedRestored.play_free, "500");

  // ===== Extension 0.3/0.4 入口（会话密钥/限额/SNIP-12 摘要）=====

  // 14. delegated key 生成（wallet_session_key_create）：私钥不出边界，
  //     只返回公钥级摘要；bindingId 缺省时由 OS 随机源生成。
  const draftReq = {
    chainId: CHAIN,
    accountAddress: "0x1234",
    allowedScopes: ["play", "buyin", "settle"],
    perTxLimit: "1000",
    perDayLimit: "5000",
    tableAllowlist: [1, 2],
    nonce: 7,
    validAfter: Number(NOW),
    validUntil: Number(NOW) + 86_400,
  };
  const created0 = JSON.parse(glue.wallet_session_key_create(JSON.stringify(draftReq)));
  assert.ok(!created0.error, `session_key_create failed: ${created0.detail}`);
  assert.equal(created0.binding.binding_id.length, 64);
  assert.equal(created0.binding.delegated_public_key.length, 66);
  assert.ok(!JSON.stringify(created0).includes("secret"));
  // 显式 bindingId 幂等 upsert（同 id 重授权替换）；bindingId 须为规范 felt
  // （< 2^251，作为 felt252 参与 SNIP-12 摘要）——生成路径已在 wasm 内掩码。
  const draft2 = { ...draftReq, bindingId: "00".repeat(31) + "ab" };
  const created2 = JSON.parse(glue.wallet_session_key_create(JSON.stringify(draft2)));
  assert.equal(created2.binding.binding_id, "00".repeat(31) + "ab");
  // 锁定/解锁后 wasm 会话清空（私钥不持久化——如实边界）
  const keysBefore = JSON.parse(glue.wallet_session_key_list());
  assert.equal(keysBefore.keys.length, 2);

  // 15. binding 状态查询（wallet_binding_status）：active / revoked（粘滞）
  const bindingJson = (over = {}) => JSON.stringify({
    bindingId: "ab".repeat(32),
    chainId: CHAIN,
    accountAddress: "0x1234",
    delegatedPublicKey: "cd".repeat(33),
    allowedScopes: ["play", "buyin", "settle"],
    perTxLimit: "1000",
    perDayLimit: "5000",
    tableAllowlist: [1, 2],
    nonce: 7,
    validAfter: Number(NOW),
    validUntil: Number(NOW) + 86_400,
    revoked: false,
    dailyUsedDay: 0,
    dailyUsedAmount: "0",
    ...over,
  });
  const st = JSON.parse(glue.wallet_binding_status(bindingJson(), NOW));
  assert.equal(st.status, "active");
  assert.equal(st.daily_remaining, "5000");
  const stRevoked = JSON.parse(glue.wallet_binding_status(bindingJson({ revoked: true }), NOW));
  assert.equal(stRevoked.status, "revoked");
  const stExhausted = JSON.parse(
    glue.wallet_binding_status(bindingJson({ dailyUsedDay: Math.floor(Number(NOW) / 86_400), dailyUsedAmount: "5000" }), NOW),
  );
  assert.equal(stExhausted.status, "exhausted");

  // 16. 限额 enforcement（wallet_session_admit）：正例 + 每类拒绝
  //     （拒绝是结构化 verdict：{admitted:false, rejected_reason}）。
  const admit = (bindingOver, req, now = NOW) =>
    JSON.parse(glue.wallet_session_admit(bindingJson(bindingOver), JSON.stringify(req), now));
  const okReq = { scope: "buyin", table_id: 1, amount: "1000", chain_id: CHAIN };
  assert.equal(admit({}, okReq).admitted, true);
  assert.equal(admit({}, { ...okReq, amount: "1001" }).rejected_reason, "OverPerTxLimit");
  assert.equal(admit({}, { ...okReq, table_id: 3 }).rejected_reason, "TableNotAllowed");
  assert.equal(admit({}, { ...okReq, scope: "transfer" }).rejected_reason, "ScopeNotAllowed");
  assert.equal(admit({}, { ...okReq, chain_id: "zchain-testnet-1" }).rejected_reason, "ChainMismatch");
  assert.equal(admit({ revoked: true }, okReq).rejected_reason, "Revoked");
  assert.equal(
    admit({ dailyUsedDay: Math.floor(Number(NOW) / 86_400), dailyUsedAmount: "4200" }, { ...okReq, amount: "801" }).rejected_reason,
    "DailyLimitExhausted",
  );
  // 形状非法仍是 error（fail-closed）
  const badAdmit = JSON.parse(glue.wallet_session_admit(bindingJson(), JSON.stringify({ scope: "wizard", amount: "1", chain_id: CHAIN }), NOW));
  assert.equal(badAdmit.error, "InvalidArgument");

  // 17. SNIP-12 授权摘要（wallet_snip12_authorize_digest）：确定性 + 字段敏感
  const digestReq = (over = {}) => JSON.stringify({
    chainId: CHAIN,
    accountAddress: "0x1234",
    delegatedPublicKey: created2.binding.delegated_public_key,
    signatureScheme: "secp256k1",
    allowedScopes: ["play", "buyin", "settle"],
    perTxLimit: "1000",
    perDayLimit: "5000",
    tableAllowlist: [1, 2],
    bindingId: "00".repeat(31) + "ab",
    nonce: 7,
    validAfter: Number(NOW),
    validUntil: Number(NOW) + 86_400,
    ...over,
  });
  const dig1 = JSON.parse(glue.wallet_snip12_authorize_digest(digestReq()));
  const dig2 = JSON.parse(glue.wallet_snip12_authorize_digest(digestReq()));
  assert.equal(dig1.digest, dig2.digest); // 确定性
  assert.match(dig1.digest, /^0x[0-9a-f]{64}$/);
  assert.ok(dig1.encode_type.startsWith("AuthorizeZChainKey("));
  assert.equal(dig1.domain.chainId, CHAIN);
  assert.equal(dig1.domain.revision, "1");
  // scope 变化 → 摘要变化（字段敏感）
  const dig3 = JSON.parse(glue.wallet_snip12_authorize_digest(digestReq({ allowedScopes: ["play"] })));
  assert.notEqual(dig1.digest, dig3.digest);

  // 18. 锁定 → 解锁后 wasm 会话密钥清空（私钥只活在会话内——如实边界）
  glue.wallet_lock();
  const unlockedFinal = JSON.parse(glue.wallet_unlock(JSON.stringify(ks), "correct horse battery staple"));
  assert.ok(!unlockedFinal.error, `final unlock failed: ${unlockedFinal.detail}`);
  const keysAfter = JSON.parse(glue.wallet_session_key_list());
  assert.equal(keysAfter.keys.length, 0);
});

/** 构造 wallet_verify_settlement_detail 的结构合法输入（校验在形状层面失败）。 */
function detailLike(over = {}) {
  return {
    hand_binding: "ab".repeat(32),
    table_id: 1,
    pot: 10,
    payout_root: "cd".repeat(32),
    rake: { total: 1 },
    plan: { gross_pot: 10, rake: 1, total_awards: 9, pots: [] },
    inputs: [{ amount: 10 }],
    payouts: [{ owner: "cd".repeat(33), amount: 9, asset_class: "PLAY", table_id: 1, pot_index: 0, runout_index: 0 }],
    ...over,
  };
}
