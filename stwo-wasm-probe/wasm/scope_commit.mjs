// 测 canonical verify 的 scope 重建承诺步骤在 wasm32 上的延迟（需 prover feature 构建）。
// 用法：node wasm/scope_commit.mjs [log_size] [n_scope] [iters]
import { readFileSync } from "node:fs";
import { performance } from "node:perf_hooks";

const logSize = Number(process.argv[2] ?? 8);
const nScope = Number(process.argv[3] ?? 1927);
const iters = Number(process.argv[4] ?? 10);
const wasmPath = process.argv[5] ?? new URL("./probe_prover_feature.wasm", import.meta.url);

const wasmBytes = readFileSync(wasmPath);
const { instance } = await WebAssembly.instantiate(wasmBytes, {});
const { memory, probe_alloc, probe_scope_commit } = instance.exports;

const ptr = probe_alloc(16); // 2 x f64

const samples = [];
for (let i = 0; i <= iters; i++) {
  const t0 = performance.now();
  const rc = probe_scope_commit(logSize, nScope, ptr);
  const dt = performance.now() - t0;
  if (rc !== 0) {
    console.error(`scope_commit failed rc=${rc}`);
    process.exit(1);
  }
  // scope commit 内部会扩 wasm 内存 → buffer 可能 detach，必须每次重建视图
  const results = new Float64Array(memory.buffer, ptr, 2);
  const label = `total_ms=${dt.toFixed(3)} (twiddles=${results[0].toFixed(3)}, tree_commit=${results[1].toFixed(3)})`;
  if (i === 0) console.log(`cold ${label}`);
  else samples.push(dt);
}
samples.sort((a, b) => a - b);
const p50 = samples[Math.min(Math.ceil(0.5 * samples.length), samples.length) - 1];
console.log(
  `wasm_scope_recommit_ms: n=${iters} p50=${p50.toFixed(3)} min=${samples[0].toFixed(3)} max=${samples[samples.length - 1].toFixed(3)}`
);
console.log(`  (log_size=${logSize} n_scope=${nScope}, SimdBackend 单线程，无 parallel feature)`);
