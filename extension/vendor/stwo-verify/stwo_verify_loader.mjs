// =============================================================================
// stwo_verify_loader.mjs — canonical STARK 验证器 wasm 的宿主侧胶水
// （node 与浏览器共用；零依赖 ES module；探针手写 C ABI 模式的延续）
//
// ABI（crates/wasm/src/lib.rs，前缀 sv_）：
//   sv_alloc(len) -> ptr ; sv_free(ptr, len) ; sv_verify(ptr, len) -> rc
//   sv_stats(ptr, cap) -> n ; sv_stats_len() -> n ; sv_last_error(ptr, cap) -> n
//
// rc 语义：0 = 完整 STARK 验证通过；-1 = 归档 borsh 解码失败；
//          -2 = 验证拒绝（形状/承诺/FRI/约束）；-3 = 内部错误。
//
// 计时（诚实口径）：墙钟一律宿主侧 performance.now() 测量（wasm32 内无时钟）。
// =============================================================================

/** 从已实例化的 WebAssembly.Instance 构造验证器门面。 */
export function createStwoVerify(instance) {
  const e = instance.exports;
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();

  function readString(rawBytes, readFn) {
    const cap = Math.max(rawBytes.length, 1);
    const ptr = e.sv_alloc(cap);
    try {
      const view = new Uint8Array(e.memory.buffer, ptr, cap);
      const n = readFn(ptr, cap);
      return decoder.decode(view.subarray(0, n));
    } finally {
      e.sv_free(ptr, cap);
    }
  }

  return {
    wasmBytesLen: e.memory.buffer.byteLength,
    verifier: 'stwo-wasm-verify',
    /**
     * 验证一份 borsh canonical 归档。
     * @param {Uint8Array} bytes
     * @returns {{rc:number, stats:object|null, error:string, elapsedMs:number}}
     *   stats 为 wasm 输出的结构化结果（verified/table_id/log_size/num_columns/
     *   transition_count/batch_digest/verifier；internal_elapsed_ms 恒为 null，
     *   wasm 内无时钟——耗时看 elapsedMs）。
     */
    verifyCanonicalProof(bytes) {
      const ptr = e.sv_alloc(bytes.length);
      let rc = -3;
      const t0 = performance.now();
      try {
        new Uint8Array(e.memory.buffer, ptr, bytes.length).set(bytes);
        rc = e.sv_verify(ptr, bytes.length);
      } finally {
        e.sv_free(ptr, bytes.length);
      }
      const elapsedMs = performance.now() - t0;
      let stats = null;
      let error = '';
      try {
        const statsLen = e.sv_stats_len();
        if (statsLen > 0) {
          stats = JSON.parse(readString(new Uint8Array(statsLen), (p, c) => e.sv_stats(p, c)));
        }
      } catch { /* stats 读不出来不掩盖 rc 结论 */ }
      try {
        error = readString(new Uint8Array(512), (p, c) => e.sv_last_error(p, c));
      } catch { /* 同上 */ }
      return { rc, stats, error, elapsedMs };
    },
    /** 自检：归档截断必须被拒（rc !== 0），用于加载后 sanity。 */
    selfTestTruncated(bytes) {
      const cut = bytes.subarray(0, Math.floor(bytes.length / 4));
      return this.verifyCanonicalProof(cut).rc !== 0;
    },
  };
}

/**
 * 从 wasm 字节实例化（node: fs.readFileSync；浏览器: fetch().arrayBuffer()）。
 *
 * 导入处理（诚实边界）：本验证器 wasm 的验证路径是纯确定性字段数学 + 哈希，
 * 理论上零 JS 导入；但 poker_texas_air 依赖图里 getrandom 的 js feature（feature
 * 统一）拖入了 5 个 wasm-bindgen 运行时占位导入（__wbindgen_placeholder__ 的
 * describe/throw/jspi 与 __wbindgen_externref_xform__ 的 externref 表操作）。
 * 对这些导入提供 **fail-closed 桩**：满足实例化链接，但一旦被真实调用即抛错
 * （绝不静默返回假值——验证器路径不应触发它们，触发即说明跑偏了）。
 */
export async function initStwoVerifyFromBytes(wasmBytes) {
  const mod = new WebAssembly.Module(wasmBytes);
  const imports = {};
  for (const im of WebAssembly.Module.imports(mod)) {
    if (im.kind !== 'function') {
      throw new Error(`stwo-verify wasm: unsupported non-function import ${im.module}.${im.name} (${im.kind})`);
    }
    (imports[im.module] ??= {})[im.name] = shimImport(im);
  }
  const linked = await WebAssembly.instantiate(mod, imports);
  // 兼容两种返回形状：Module 重载直接给 Instance；bytes 重载给 { module, instance }。
  const instance = linked instanceof WebAssembly.Instance ? linked : linked.instance;
  return createStwoVerify(instance);
}

function shimImport(im) {
  // externref 表操作：grow 返回 -1（增长失败，fail-closed）；其余为 no-op 形状。
  if (im.module === '__wbindgen_externref_xform__') {
    if (im.name.endsWith('_grow')) return () => -1;
    return () => {};
  }
  // __wbindgen_placeholder__（describe/throw/jspi 等）：验证路径不应调用；
  // 调用即抛错（绝不静默）。
  return () => {
    throw new Error(
      `stwo-verify wasm: shim import called unexpectedly: ${im.module}.${im.name} ` +
      '(verify path is deterministic; this means non-verify code ran — refusing)',
    );
  };
}

/** 从 URL 实例化（浏览器/同源静态服务）。 */
export async function initStwoVerifyFromUrl(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`stwo-verify wasm fetch ${res.status}: ${url}`);
  return initStwoVerifyFromBytes(await res.arrayBuffer());
}

/** stats JSON 里要二次透传的字段编码辅助（batch_digest 已是 hex）。 */
export function u8ToBase64(bytes) {
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

export function base64ToU8(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// node 下无 btoa/atob 的兜底（Node >= 16 已内置全局 btoa/atob，此处只是防御）。
export function base64ToU8Safe(b64) {
  if (typeof atob === 'function') return base64ToU8(b64);
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

export function u8ToBase64Safe(bytes) {
  if (typeof btoa === 'function') return u8ToBase64(bytes);
  return Buffer.from(bytes).toString('base64');
}
