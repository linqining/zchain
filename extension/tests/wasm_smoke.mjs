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

  // 9. 脱敏：note 列表不含 spend secret / nullifier / 私钥
  const notes = JSON.parse(glue.wallet_get_notes());
  const blob = JSON.stringify(notes);
  assert.ok(!blob.includes("spend_secret"));
  assert.ok(!blob.includes("nullifier"));
  assert.ok(blob.length < 4096);
});
