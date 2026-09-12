// M6-ACC-1 浏览器验证吞吐 — 页面逻辑（见 m6acc1.html 头注释）。
//
// 范围口径（如实）：v1 客户端本地验证在浏览器里经 wallet-core wasm 的
// JSON 入口执行——
//   1) wallet_preview(kind=settle)：borsh 解析 + 守恒预检 + 预览摘要；
//   2) wallet_sign(kind=settle)：内部对签名完备后的记录执行
//      poker-appchain validate_settlement 全量校验（守恒/费率/分账/P 层
//      ECDSA 签名覆盖/手牌证明绑定），fail-closed，篡改 → VerifierRejected。
//   3) 校验中复用 wallet-core 的 poseidon/blake2b/secp256k1 实现（密码学
//      零 JS）。
// 软确认链 verify_chain / 批次根复算 / attestation 结构校验在 wallet-core
// native verifier（poker-wallet/src/verifier.rs）同一实现下有测试覆盖，
// 但 0.1 的 wasm JSON 面未暴露这些入口（0.2 sync 缝），因此不在浏览器
// 循环内；完整 STARK 验证（stwo-wasm）不在 v1。见 extension/ACCEPTANCE.md。

import init, {
  wallet_core_meta,
  wallet_create,
  wallet_preview,
  wallet_sign,
} from '../../vendor/wallet-core/wallet_core_wasm.js';

const params = new URLSearchParams(location.search);
const ROUNDS = Math.max(1, parseInt(params.get('rounds') || '50', 10) || 50);
const FIXTURES = 10; // 手 1..9 正例 + 手 10 负例（伪造签名）

const $progress = document.getElementById('progress');
const $verdict = document.getElementById('verdict');
const $summary = document.getElementById('summary');

const median = (xs) => {
  if (!xs.length) return 0;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};
const pct = (xs, p) => {
  if (!xs.length) return 0;
  const s = [...xs].sort((a, b) => a - b);
  const idx = Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1);
  return s[Math.max(0, idx)];
};
const avg = (xs) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0);

// 堆判据：末 3 轮均值 vs 首 3 轮均值增幅 < 20%，且最后 10 轮无持续增长
// 趋势——"持续"= 最长连续递增 ≥ 5 轮 且 末 10 轮极差超过噪声带
// max(32KB, 首3轮均值×2%)（带内微小抖动不算增长趋势）。
function heapStats(vals) {
  if (!vals || vals.some((v) => v === null || v === undefined)) return null;
  const first3 = avg(vals.slice(0, 3));
  const last3 = avg(vals.slice(-3));
  const growthPct = first3 > 0 ? ((last3 - first3) / first3) * 100 : 0;
  const tail = vals.slice(-10);
  let maxRun = 0;
  let run = 0;
  for (let i = 1; i < tail.length; i++) {
    if (tail[i] > tail[i - 1]) {
      run += 1;
      maxRun = Math.max(maxRun, run);
    } else {
      run = 0;
    }
  }
  const tailBand = Math.max(32 * 1024, first3 * 0.02);
  const tailRange = tail.length ? Math.max(...tail) - Math.min(...tail) : 0;
  const sustainedTrend = maxRun >= 5 && tailRange > tailBand;
  return {
    first3_avg_bytes: Math.round(first3),
    last3_avg_bytes: Math.round(last3),
    growth_pct: Number(growthPct.toFixed(2)),
    tail10_max_consecutive_increase: maxRun,
    tail10_range_bytes: Math.round(tailRange),
    tail_noise_band_bytes: Math.round(tailBand),
    max_bytes: Math.round(Math.max(...vals)),
    pass: growthPct < 20 && !sustainedTrend,
    criteria: '末3轮均值 vs 首3轮均值增幅 < 20% 且 最后10轮无持续增长（连续递增≥5轮且极差超噪声带 max(32KB, 首3均值×2%) 才算）',
  };
}

function render(result) {
  $progress.textContent = `完成：${result.meta.rounds} 轮 × ${result.meta.hands_per_round} 手（正例 9 + 负例 1/轮）`;
  $verdict.textContent = `${result.verdict} — correct ${result.stats.correct}/${result.stats.hands_total}, median ${result.stats.median_ms} ms/手, heap growth ${result.heap ? result.heap.growth_pct + '%' : 'n/a'}`;
  $verdict.className = `verdict ${result.verdict === 'PASS' ? 'pass' : 'fail'}`;
  $verdict.style.display = 'inline-block';
  $summary.textContent = JSON.stringify(result, null, 2);
}

async function main() {
  const t0 = performance.now();
  // wasm 实例导出（仅用于读线性内存尺寸）；wrapper 函数用命名导入
  // （init() 返回原始导出，指针语义，不能直接当 JSON 字符串接口用）。
  const wasmExports = await init();
  const meta = JSON.parse(wallet_core_meta());

  // 会话钱包（计时段之外的一次性准备；profile=test 的快速 Argon2 参数，
  // 仅用于测试/冒烟——与扩展生产 interactive 档无关本测试口径）。
  const created = JSON.parse(wallet_create('m6acc1-perf-password', 'test'));
  if (created.error) throw new Error('wallet_create failed: ' + created.detail);

  const fixtures = [];
  for (let i = 1; i <= FIXTURES; i++) {
    const name = `hand_${String(i).padStart(2, '0')}.json`;
    const res = await fetch(`../fixtures/m6acc1/${name}`, { cache: 'no-store' });
    if (!res.ok) throw new Error(`fixture missing: ${name}`);
    fixtures.push(await res.json());
  }
  const setup_ms = Number((performance.now() - t0).toFixed(1));

  // 收集协议：runner（CDP 侧）逐轮取走每轮明细，页面只保留紧凑摘要
  // （每轮 6 个数值，~百字节级）——这样"GC 后留存堆"度量的是验证工作负载
  // 本身的留存，而非 harness 自己的报告累积（后者是泄漏测量的已知混杂项）。
  // runner 2s 内未确认则转入 standalone 兜底：页面自留全部明细（此模式下
  // 留存堆含报告累积，结果 JSON 如实标注）。
  let runnerMode = null; // 'cdp-collect' | 'standalone-self-retain'
  const roundSummaries = [];
  const selfRetained = [];
  const handDurations = [];
  let nonce = 1;
  let correct = 0;
  let handsTotal = 0;
  const sleep = (ms) => new Promise((res) => setTimeout(res, ms));

  const offerRound = async (round) => {
    if (runnerMode === 'standalone-self-retain') {
      selfRetained.push(round);
      return;
    }
    window.__M6ACC1_ROUND_ACK = false;
    window.__M6ACC1_ROUND = round;
    window.__M6ACC1_ROUND_READY = true;
    const offerT0 = Date.now();
    while (!window.__M6ACC1_ROUND_ACK && Date.now() - offerT0 < 2000) {
      await sleep(5);
    }
    if (window.__M6ACC1_ROUND_ACK) {
      runnerMode = 'cdp-collect';
    } else {
      runnerMode = 'standalone-self-retain';
      window.__M6ACC1_ROUND = null;
      selfRetained.push(round);
    }
  };

  for (let r = 1; r <= ROUNDS; r++) {
    const rt0 = performance.now();
    const hands = [];
    for (const fx of fixtures) {
      const now = Math.floor(Date.now() / 1000);
      const reqBase = {
        kind: 'settle',
        asset_class: 'PLAY',
        chain_id: fx.chain_id,
        domain: 'zchain',
        abi_version: 1,
        expiry: now + 3600,
        policy_borsh: fx.policy_borsh,
        record_borsh: fx.record_borsh,
      };
      // 面 1：preview（解析 + 守恒预检 + 预览摘要）
      const tp0 = performance.now();
      const prev = JSON.parse(
        wallet_preview(JSON.stringify({ ...reqBase, nonce: nonce++ }), String(now)),
      );
      const tp1 = performance.now();
      // 面 2：sign（validate_settlement 全量校验 fail-closed + 结算操作输出）
      const ts0 = performance.now();
      const sign = JSON.parse(
        wallet_sign(JSON.stringify({ ...reqBase, nonce: nonce++ }), String(now)),
      );
      const ts1 = performance.now();

      const previewOk = !prev.error;
      const expectReject = fx.expected === 'reject';
      const signOk = expectReject
        ? sign.error === 'VerifierRejected'
        : !sign.error && typeof sign.operation_borsh === 'string' && sign.operation_borsh.length > 0;
      const ok = previewOk && signOk;
      handsTotal += 1;
      if (ok) correct += 1;
      const totalMs = (tp1 - tp0) + (ts1 - ts0);
      handDurations.push(totalMs);
      hands.push({
        hand: fx.hand,
        variant: fx.variant,
        expected: fx.expected,
        preview_ok: previewOk,
        sign_error: sign.error ?? null,
        ok,
        preview_ms: Number((tp1 - tp0).toFixed(3)),
        sign_ms: Number((ts1 - ts0).toFixed(3)),
        total_ms: Number(totalMs.toFixed(3)),
      });
    }
    // 泄漏判据采样：记录未 GC 原始堆（信息性——只反映分配 churn），
    // 然后强制 GC（runner 以 --js-flags=--expose-gc 启动；gc 两次覆盖跨代
    // 回收）再采样"GC 后留存堆"作为泄漏判据。
    const heapRaw = performance.memory ? performance.memory.usedJSHeapSize : null;
    if (window.gc) { window.gc(); window.gc(); }
    const round = {
      round: r,
      all_ok: hands.every((h) => h.ok),
      hands,
      round_ms: Number((performance.now() - rt0).toFixed(1)),
      heap_after_gc_bytes: performance.memory ? performance.memory.usedJSHeapSize : null,
      heap_raw_bytes_before_gc: heapRaw,
      wasm_mem_bytes: wasmExports.memory.buffer.byteLength,
    };
    roundSummaries.push({
      round: r,
      all_ok: round.all_ok,
      round_ms: round.round_ms,
      heap_after_gc_bytes: round.heap_after_gc_bytes,
      heap_raw_bytes_before_gc: heapRaw,
      wasm_mem_bytes: round.wasm_mem_bytes,
    });
    await offerRound(round);
    $progress.textContent = `第 ${r}/${ROUNDS} 轮完成（correct ${correct}/${handsTotal}）`;
  }

  const heaps = roundSummaries.map((x) => x.heap_after_gc_bytes);
  const heapsRaw = roundSummaries.map((x) => x.heap_raw_bytes_before_gc);
  const wasmMems = roundSummaries.map((x) => x.wasm_mem_bytes);
  const allCorrect = correct === handsTotal;
  // 泄漏判据 = GC 后留存堆序列（留存 = 真泄漏/合法留存数据的判别对象）；
  // 原始堆序列仅信息性记录。wasm 线性内存不做 GC 语义，直接判趋势。
  const heap = heapStats(heaps);
  const heapRawInfo = heapStats(heapsRaw);
  const wasmMem = heapStats(wasmMems);
  // 辅助门槛（如实标注：计划原文 M6-ACC-1 = "全部通过且无内存泄漏"；
  // ≤500ms/手 属 M4-ACC-5 的中位口径，这里仅作为附加信息性门槛断言 p95）。
  const p95Ms = pct(handDurations, 95);
  const p95Under500 = p95Ms <= 500;

  const verdict = allCorrect && p95Under500 && (heap === null ? true : heap.pass) && (wasmMem === null ? true : wasmMem.pass)
    ? 'PASS'
    : 'FAIL';

  const result = {
    acceptance: 'M6-ACC-1 浏览器验证吞吐：连续 10 手证明验证，全部通过且无内存泄漏（长会话）',
    verdict,
    meta: {
      date: new Date().toISOString(),
      user_agent: navigator.userAgent,
      rounds: ROUNDS,
      hands_per_round: FIXTURES,
      hands_total: handsTotal,
      wallet_core: meta,
      harness: 'extension/tests/perf/m6acc1.html + m6acc1_page.js（wallet-core wasm vendor 产物与扩展同源）',
      setup_ms,
      heap_api: performance.memory ? 'performance.memory.usedJSHeapSize (--enable-precise-memory-info)' : 'unavailable',
      forced_gc: typeof window.gc === 'function' ? 'window.gc available (--js-flags=--expose-gc)；每轮采样 GC 后留存堆' : 'unavailable',
      heap_criteria: '泄漏判据 = 每轮强制 GC 后的留存堆序列：末3轮均值 vs 首3轮均值增幅 < 20% 且 最后10轮无持续增长（连续递增≥5轮且极差超噪声带 max(32KB, 首3均值×2%) 才算）；wasm 线性内存同判据',
      collection_mode: runnerMode,
      scope_boundary: [
        '浏览器循环面 = wallet-core wasm 的 wallet_preview + wallet_sign(settle)，后者内部执行 validate_settlement 全量校验（守恒/费率/分账/P层ECDSA签名覆盖/手牌绑定）',
        '软确认链 verify_chain / 批次根复算 / attestation 结构校验：wallet-core native verifier 同一实现有测试覆盖；0.1 wasm JSON 面未暴露（0.2 sync 缝），不在浏览器循环内',
        '完整 STARK 验证 wasm 化（stwo-wasm）不在 v1',
      ],
    },
    stats: {
      correct,
      hands_total: handsTotal,
      all_correct: allCorrect,
      median_ms: Number(median(handDurations).toFixed(3)),
      mean_ms: Number(avg(handDurations).toFixed(3)),
      p95_ms: Number(p95Ms.toFixed(3)),
      max_ms: Number(Math.max(...handDurations).toFixed(3)),
      p95_under_500ms: p95Under500,
      total_wall_ms: Number((performance.now() - t0).toFixed(1)),
    },
    heap,
    heap_raw_informational: heapRawInfo,
    wasm_linear_memory: wasmMem,
    // cdp-collect 模式下 rounds 明细由 runner 逐轮取走合并（页面只留摘要）；
    // standalone 模式 = 页面自留明细（留存堆含报告累积，判据口径放宽说明见上）。
    rounds: runnerMode === 'cdp-collect' ? roundSummaries : selfRetained,
    round_summaries: runnerMode === 'cdp-collect' ? roundSummaries : [],
  };

  window.__M6ACC1_RESULT = result;
  window.__M6ACC1_DONE = true;
  console.log('M6ACC1_RESULT ' + JSON.stringify(result));
  render(result);
}

main().catch((e) => {
  window.__M6ACC1_RESULT = { verdict: 'ERROR', error: String(e && e.stack ? e.stack : e) };
  window.__M6ACC1_DONE = true;
  console.error('M6ACC1_FATAL', e);
  $progress.textContent = `错误：${e}`;
  $verdict.textContent = 'ERROR';
  $verdict.className = 'verdict fail';
  $verdict.style.display = 'inline-block';
});
