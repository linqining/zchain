#!/usr/bin/env node
// =============================================================================
// bench.mjs — canonical 真证明 wasm 验证基准（path A 验收数据源）
//
// 口径：
// - 输入：proofs/canonical_table*.bin（gen-canonical 产出的真实 borsh 归档，
//   poker_texas_air prove 路径出证，wasm 侧只做 verify）。
// - 每份证明预热 1 次后连续验证 N 次（默认 12），取最近秩分位 p50/p95；
//   对照 500ms 门槛与探针 0.4–0.8s 预估区间，如实输出、不造假。
// - 负例：每份证明各跑两类篡改（中段字节翻转=STARK 证明体、公共字段区翻转），
//   全部必须被拒（rc !== 0）；另跑截断归档（期望 rc=-1 解码失败）。
// - 计时：墙钟一律宿主侧 performance.now()（wasm32 内无时钟）。
//
// 用法：node harness/bench.mjs [wasm路径] [proofs目录] [N]
// 输出：stdout 明细 + logs/wasm_bench_result.json（结构化结果）
// =============================================================================
import { readFileSync, writeFileSync, mkdirSync, readdirSync } from 'node:fs';
import { performance } from 'node:perf_hooks';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { initStwoVerifyFromBytes } from '../wasm/stwo_verify_loader.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');
const WASM_PATH = process.argv[2]
  ?? path.join(ROOT, 'target/wasm32-unknown-unknown/release/stwo_verify_wasm.wasm');
const PROOFS_DIR = process.argv[3] ?? path.join(ROOT, 'proofs');
const N_ITERS = Number(process.argv[4] ?? 12);
const GATE_MS = 500; // path A 验收门槛（探针报告 §4：预估 0.4–0.8s，可能超）

function percentile(sorted, p) {
  const rank = Math.min(Math.max(Math.ceil(p * sorted.length), 1), sorted.length);
  return sorted[rank - 1];
}

function hex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function main() {
  const wasmBytes = readFileSync(WASM_PATH);
  const v = await initStwoVerifyFromBytes(wasmBytes);
  const proofFiles = readdirSync(PROOFS_DIR)
    .filter((f) => f.startsWith('canonical_table') && f.endsWith('.bin'))
    .sort();
  if (proofFiles.length === 0) {
    console.error(`no canonical_table*.bin in ${PROOFS_DIR} — 先跑 gen-canonical`);
    process.exit(2);
  }

  const lines = [];
  const log = (s) => {
    console.log(s);
    lines.push(s);
  };
  log(`stwo_wasm_bench wasm_bytes=${wasmBytes.length} node=${process.version} n_iters=${N_ITERS} gate_ms=${GATE_MS}`);
  log(`proofs_dir=${PROOFS_DIR} proofs=${proofFiles.length}`);

  const results = { wasm_bytes: wasmBytes.length, node: process.version, n_iters: N_ITERS, gate_ms: GATE_MS, proofs: [], negatives: [] };
  let allVerified = true;
  let allRejected = true;
  let overallP50 = [];
  let overallP95 = [];

  for (const file of proofFiles) {
    const bytes = readFileSync(path.join(PROOFS_DIR, file));
    // 预热 1 次（首次 JIT/表初始化不计入稳态样本；冷启动单独记录）。
    const cold = v.verifyCanonicalProof(bytes);
    if (cold.rc !== 0) {
      log(`FAIL ${file}: genuine proof rejected rc=${cold.rc} error=${cold.error}`);
      allVerified = false;
      results.proofs.push({ file, bytes: bytes.length, accepted: false, rc: cold.rc, error: cold.error });
      continue;
    }
    const coldMs = cold.elapsedMs;
    const samples = [];
    let lastStats = cold.stats;
    for (let i = 0; i < N_ITERS; i++) {
      const r = v.verifyCanonicalProof(bytes);
      if (r.rc !== 0) {
        log(`FAIL ${file}: rc=${r.rc} at iter ${i} error=${r.error}`);
        allVerified = false;
        break;
      }
      samples.push(r.elapsedMs);
      lastStats = r.stats;
    }
    const sorted = [...samples].sort((a, b) => a - b);
    const p50 = percentile(sorted, 0.5);
    const p95 = percentile(sorted, 0.95);
    overallP50.push(p50);
    overallP95.push(p95);
    const withinGate = p95 <= GATE_MS;
    log(
      `PROOF ${file} bytes=${bytes.length} table_id=${lastStats?.table_id} log_size=${lastStats?.log_size} ` +
      `cols=${lastStats?.num_columns} transitions=${lastStats?.transition_count} ` +
      `digest=${(lastStats?.batch_digest ?? '').slice(0, 16)}… ` +
      `cold_ms=${coldMs.toFixed(1)} min=${sorted[0].toFixed(1)} p50=${p50.toFixed(1)} p95=${p95.toFixed(1)} max=${sorted[sorted.length - 1].toFixed(1)} ` +
      `gate_500ms=${withinGate ? 'WITHIN' : 'OVER'}`,
    );
    log(`SAMPLES ${file} ${samples.map((s) => s.toFixed(1)).join(', ')}`);
    results.proofs.push({
      file, bytes: bytes.length, accepted: true, cold_ms: coldMs,
      p50_ms: p50, p95_ms: p95, min_ms: sorted[0], max_ms: sorted[sorted.length - 1],
      within_gate_500ms: withinGate, stats: lastStats,
    });

    // ===== 负例（必须拒绝）=====
    const negatives = [
      { name: 'mid_byte_flip', mutate: (b) => { const c = Uint8Array.from(b); c[Math.floor(c.length / 2)] ^= 0x01; return c; } },
      { name: 'header_field_flip', mutate: (b) => { const c = Uint8Array.from(b); c[16] ^= 0x01; return c; } },
      { name: 'truncated_quarter', mutate: (b) => b.subarray(0, Math.floor(b.length / 4)) },
    ];
    for (const neg of negatives) {
      const r = v.verifyCanonicalProof(neg.mutate(bytes));
      const rejected = r.rc !== 0;
      if (!rejected) allRejected = false;
      log(`NEGATIVE ${file}/${neg.name}: rc=${r.rc} ${rejected ? `(rejected, ok)${r.error ? ' error=' + r.error.slice(0, 90) : ''}` : '!!! TAMPERED ACCEPTED !!!'}`);
      results.negatives.push({ file, kind: neg.name, rc: r.rc, rejected });
    }
  }

  const op50 = percentile([...overallP50].sort((a, b) => a - b), 0.5);
  const op95 = percentile([...overallP95].sort((a, b) => a - b), 0.95);
  results.all_genuine_accepted = allVerified;
  results.all_negatives_rejected = allRejected;
  results.overall_p50_ms = op50;
  results.overall_p95_ms = op95;
  log(`SUMMARY proofs=${proofFiles.length} overall_p50_ms=${op50.toFixed(1)} overall_p95_ms=${op95.toFixed(1)} ` +
    `gate_500ms_p95=${op95 <= GATE_MS ? 'WITHIN' : 'OVER'} ` +
    `all_accepted=${allVerified} all_negatives_rejected=${allRejected}`);
  // 与探针预估（0.4–0.8s）对照的结论行：数值自己说话。
  log(`VS_ESTIMATE probe_estimate_ms=400-800 measured_p50_ms=${op50.toFixed(1)} measured_p95_ms=${op95.toFixed(1)}`);

  mkdirSync(path.join(ROOT, 'logs'), { recursive: true });
  writeFileSync(path.join(ROOT, 'logs/wasm_bench_result.json'), JSON.stringify(results, null, 2) + '\n');
  writeFileSync(path.join(ROOT, 'logs/wasm_bench_raw.txt'), lines.join('\n') + '\n');
  const ok = allVerified && allRejected;
  process.exit(ok ? 0 : 1);
}

main().catch((e) => {
  console.error('bench error:', e);
  process.exit(1);
});
