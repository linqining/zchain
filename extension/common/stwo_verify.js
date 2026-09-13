// =============================================================================
// extension/common/stwo_verify.js — canonical STARK 验证器 wasm 加载与调用门面
// （0.4 / stwo-wasm path A）
//
// 验证语义唯一边界：本模块只加载 stwo-wasm-verify 构建的验证器 wasm
// （vendor/stwo-verify/，含哈希清单）并把归档字节转发给它；**任何 JS 侧
// FRI/Merkle/约束/哈希重实现都被禁止**。验证对象是 poker_texas_air canonical
// 归档（borsh ArchivedCanonicalTaggedProof，网关 proof 通道的 payload_b64）。
//
// 产物（vendor/stwo-verify/，构建来源见 MANIFEST.json 与
// docs/stwo-wasm-path-a.md）：
//   vendor/stwo-verify/stwo_verify_wasm.wasm      （手写 C ABI cdylib）
//   vendor/stwo-verify/stwo_verify_loader.mjs     （宿主侧胶水，node/浏览器共用）
//
// ABI：sv_alloc/sv_free/sv_verify/sv_stats/sv_stats_len/sv_last_error。
// rc 语义：0=验证通过；-1=归档解码失败；-2=验证拒绝；-3=内部错误。
// 计时：wasm32 内无时钟（std::time::Instant 会 panic），墙钟一律宿主侧测。
// =============================================================================

import { initStwoVerifyFromBytes } from '../vendor/stwo-verify/stwo_verify_loader.mjs';

const WASM_URL = new URL('../vendor/stwo-verify/stwo_verify_wasm.wasm', import.meta.url);

let initPromise = null;

/** 加载并实例化 STARK 验证器 wasm（幂等；页面生命周期内复用同一实例）。 */
export function initStwoVerify() {
  if (!initPromise) {
    initPromise = (async () => {
      const res = await fetch(WASM_URL);
      if (!res.ok) throw new Error(`stwo-verify wasm fetch ${res.status}`);
      return initStwoVerifyFromBytes(await res.arrayBuffer());
    })();
    initPromise.catch(() => { initPromise = null; });
  }
  return initPromise;
}

/**
 * 验证一份 canonical 归档字节（完整 STARK 验证，含公开 scope 承诺重建）。
 * @param {Uint8Array} bytes borsh 归档字节
 * @returns {Promise<{rc:number, stats:object|null, error:string, elapsedMs:number}>}
 *   stats 含 verified/table_id/log_size/num_columns/transition_count/
 *   batch_digest/verifier（验证器版本串，展示用）。elapsedMs 为宿主墙钟。
 */
export async function verifyCanonicalArchive(bytes) {
  const v = await initStwoVerify();
  return v.verifyCanonicalProof(bytes);
}
