// M4-ACC-5 探针：node 加载 wasm 验证器，跑 N 次验证取分位。
// 用法：node wasm/verify.mjs <case.bin> [n_iters] [wasm_path]
import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";

const casePath = process.argv[2];
const nIters = Number(process.argv[3] ?? 25);
const wasmPath = process.argv[4] ?? new URL("../target/wasm32-unknown-unknown/release/stwo_wasm_probe.wasm", import.meta.url);

if (!casePath) {
  console.error("usage: node wasm/verify.mjs <case.bin> [n_iters] [wasm_path]");
  process.exit(2);
}

const wasmBytes = readFileSync(wasmPath);
const { instance } = await WebAssembly.instantiate(wasmBytes, {});
const { memory, probe_alloc, probe_free, probe_verify, probe_last_error } = instance.exports;

function percentile(sorted, p) {
  const rank = Math.min(Math.max(Math.ceil(p * sorted.length), 1), sorted.length);
  return sorted[rank - 1];
}

function loadCase(bytes) {
  const ptr = probe_alloc(bytes.length);
  const view = new Uint8Array(memory.buffer, ptr, bytes.length);
  view.set(bytes);
  return ptr;
}

function readLastError() {
  const buf = new Uint8Array(memory.buffer, 0, 512); // 复用内存头部 512B 暂存（先 alloc 保护）
  // 更稳妥：分配专用缓冲
  const p = probe_alloc(512);
  const v = new Uint8Array(memory.buffer, p, 512);
  const n = probe_last_error(p, 512);
  const msg = new TextDecoder().decode(v.subarray(0, n));
  return msg;
}

const caseBytes = readFileSync(casePath);
console.log(`wasm_bytes=${wasmBytes.length} case_bytes=${caseBytes.length} node=${process.version}`);

// 冷启动第一次（含实例化后的首次验证路径 JIT 暖机）
{
  const t0 = performance.now();
  const ptr = loadCase(caseBytes);
  const rc = probe_verify(ptr, caseBytes.length);
  const coldMs = performance.now() - t0;
  console.log(`cold_first_verify: rc=${rc} ms=${coldMs.toFixed(3)}`);
  if (rc !== 0) {
    console.error(`genuine case FAILED rc=${rc}: ${readLastError()}`);
    process.exit(1);
  }
}

// 稳态基准
const samples = [];
for (let i = 0; i < nIters; i++) {
  const ptr = loadCase(caseBytes);
  const t0 = performance.now();
  const rc = probe_verify(ptr, caseBytes.length);
  const dt = performance.now() - t0;
  if (rc !== 0) {
    console.error(`verify failed at iter ${i}: rc=${rc} ${readLastError()}`);
    process.exit(1);
  }
  samples.push(dt);
}
const sorted = [...samples].sort((a, b) => a - b);
const min = sorted[0];
const p50 = percentile(sorted, 0.5);
const p95 = percentile(sorted, 0.95);
const max = sorted[sorted.length - 1];
console.log(
  `wasm_verify_ms: n=${nIters} min=${min.toFixed(3)} p50=${p50.toFixed(3)} p95=${p95.toFixed(3)} max=${max.toFixed(3)}`
);
console.log(`wasm_verify_samples_ms: [${samples.map((s) => s.toFixed(3)).join(", ")}]`);

// 篡改检测：翻转 proof 中间一个字节，期望 rc != 0（验证器必须拒绝）。
{
  const tampered = Uint8Array.from(caseBytes);
  const mid = Math.floor(tampered.length / 2);
  tampered[mid] ^= 0x01;
  const ptr = loadCase(tampered);
  const rc = probe_verify(ptr, tampered.length);
  console.log(`tamper_test: rc=${rc} ${rc === 0 ? "!!! TAMPERED PROOF ACCEPTED !!!" : "(rejected, ok)"}`);
}
