// =============================================================================
// extension/common/wallet_core.js — wallet-core WASM 加载与 JSON 门面
//
// 密码学唯一边界：本模块只加载 poker-wallet 编译出的 wallet_core_wasm 并转发
// JSON 调用；**任何 JS 侧摘要/签名/加密实现都被禁止**（plan §6.12.3/§6.12.4）。
//
// 产物（已提交在 vendor/wallet-core/，构建命令见 extension/README.md）：
//   vendor/wallet-core/wallet_core_wasm.js     （wasm-bindgen --target web 胶水）
//   vendor/wallet-core/wallet_core_wasm_bg.wasm
//
// 调用约定（与 poker-wallet/src/wasm.rs 的 ABI 约定一致）：
// - 金额为十进制字符串；公钥/承诺/摘要为小写 hex；
// - 返回 JSON；错误形态 {error: "<STABLE_CODE>", detail: "..."} → 抛 WalletCoreError。
// =============================================================================

import __wbg_init, {
  wallet_core_meta,
  wallet_create,
  wallet_unlock,
  wallet_lock as wc_wallet_lock,
  wallet_persist,
  wallet_faucet_play,
  wallet_get_notes,
  wallet_preview,
  wallet_sign,
  wallet_sign_settle_input,
} from '../vendor/wallet-core/wallet_core_wasm.js';

let initPromise = null;

/** 加载并实例化 WASM（幂等；service worker 生命周期内复用同一实例）。 */
export function initWalletCore() {
  if (!initPromise) {
    initPromise = __wbg_init(new URL('../vendor/wallet-core/wallet_core_wasm_bg.wasm', import.meta.url));
  }
  return initPromise;
}

/** wallet-core 错误：code 是稳定契约（validation/UI/测试依赖），detail 仅供人读。 */
export class WalletCoreError extends Error {
  constructor(code, detail) {
    super(`${code}: ${detail ?? ''}`);
    this.name = 'WalletCoreError';
    this.code = code;
    this.detail = detail ?? '';
  }
}

/**
 * 调用一个 wasm 入口：JSON 解析 + 错误归一。
 * @param {string} fn 导出函数名
 * @param {...string} args 字符串参数（ABI 约定 String -> String）
 */
export async function callCore(fn, ...args) {
  await initWalletCore();
  const registry = {
    wallet_core_meta,
    wallet_create,
    wallet_unlock,
    wallet_lock: wc_wallet_lock,
    wallet_persist,
    wallet_faucet_play,
    wallet_get_notes,
    wallet_preview,
    wallet_sign,
    wallet_sign_settle_input,
  };
  const f = registry[fn];
  if (!f) throw new WalletCoreError('InvalidArgument', `unknown core entry ${fn}`);
  let parsed;
  try {
    parsed = JSON.parse(f(...args));
  } catch (e) {
    // wasm trap / 非 JSON 输出：fail-closed。
    throw new WalletCoreError('Codec', `core ${fn} returned unparsable output`);
  }
  if (parsed && typeof parsed === 'object' && typeof parsed.error === 'string') {
    throw new WalletCoreError(parsed.error, parsed.detail);
  }
  return parsed;
}
