# stwo-wasm 可行性探针报告（M4-ACC-5 / 发布前置 C1 前置调研）

**结论：CONDITIONAL（有条件 GO）。**

- **浏览器端完整 STARK 验证 ≤500ms：可达**，但不是在当前 canonical 证明格式原样照搬的情况下达成。
- 实测：与 canonical 同规模（列数/域/FRI 参数对齐）的 demo AIR，**Blake2s 承诺哈希**下 wasm32 验证 **p50 ≈ 7.7ms**（node v24.4.1，N=25），距 500ms 有 **~65 倍余量**。
- 硬阻塞：canonical 现用的 **Poseidon252 承诺哈希被 stwo 2.3 在 wasm32 上以 `#[cfg(not(target_arch = "wasm32"))]` 整体编译排除**。携带 Poseidon252 承诺的现有 canonical 证明**无法**用 crates.io `stwo` 2.3 原样在浏览器验证。
- 条件（三选一，详见 §6 建议）：给上游提 issue 解除 wasm32 cfg 门（小补丁），或 canonical 栈换 Blake2s 承诺（协议级原子变更），或探针已证明的 Blake2s 路径直接接入新证明。
- 若解除 Poseidon 门：wasm 延迟**估算**约 0.4–0.8s（估算依据见 §5.3），**marginal**，不保证 ≤500ms。

- 探针日期：2026-09-12/13（本地时间跨午夜）
- stwo 版本：**crates.io `stwo` 2.3.0**（`stwo-constraint-framework` 2.3.0、`stwo-std-shims` 1.0.0）
- 环境：macOS arm64（Apple M3 Pro，36 GB），rustc `nightly-2026-04-15`（zchain 根 toolchain pin；验证器路径 stable 1.x 亦可编译，见 §1.4），node **v24.4.1**，wasm32-unknown-unknown
- 探针工程：`stwo-wasm-probe/`（独立 lockfile，未加入 zchain workspace，未改动其他目录）；原始输出在 `stwo-wasm-probe/logs/`

---

## 0. 探针设计

为避免"拿 toy 数据外推失真"，demo AIR 刻意对齐 `poker_texas_air` canonical AIR 的**验证器成本决定因素**（约束内容本身对验证成本不敏感，成本由列数、域大小、FRI 参数、承诺哈希决定）：

| 维度 | canonical（只读采集） | 探针 demo |
|---|---|---|
| 树结构 | scope 树 + trace 树 + LogUp 交互树（3 棵） | 相同 3 棵 |
| PCS | `pow_bits=10, FriConfig{log_blowup=1, log_last_layer_degree=0, n_queries=30, fold_step=1}`（`prover_context.rs` L43） | 逐字段相同 |
| 哈希器 | `Poseidon252MerkleChannel` | Poseidon252 + Blake2s 双跑 |
| 列数（log8 单手） | tree0=1927, tree1=5392, tree2=116（QM31 base 拆分） | 参数化：1/60 → 1000/2000 → **1927/5392**（精确同宽） |
| log_size | 8（单手，`MIN_LOG_SIZE=8`）～ 10（`BATCH_LOG_SIZE=10`） | 8 与 10 |
| 组件 | `FrameworkComponent` + `finalize_logup_in_pairs` + 29 列 LogUp（`relation!(CanonicalRange8,1)` 同形） | 相同结构（56 字节查找两两批 + 1 张 256 项表） |

canonical 列数采集方式：`tools/eval_consts.py` 机械求值 `texas_canonical_air.rs` 的 const 链（`NUM_COLUMNS=5391`、`PREPROCESSED_COLUMNS=1927`、`RANGE_INTERACTION_COLUMNS=29→116` base 列），与 `verify_canonical_stark`（L9444）三棵树的 `scheme.commit` 调用逐一对应。

**真实性声明**：下文所有"实测"数字均来自真实运行（原始输出在 `stwo-wasm-probe/logs/*.txt`，本文只做摘录）；标"估算"的是外推值，方法与系数全部给出。

---

## 1. 步骤1：依赖可行性（wasm32 编译）

### 1.1 依赖树（`cargo tree -e normal`，default features，109 包）

`logs/cargo_tree_stwo_default.txt`。关键项：

- **无 rayon**（`parallel` 是 opt-in feature）、**无 C++/系统依赖**。
- `starknet-crypto 0.6.2`（Poseidon 哈希用，纯 Rust）→ `ark-ff/num-bigint/crypto-bigint` 等，全部纯 Rust。
- wasm32 下传递引入 `wasm-bindgen`/`js-sys`/`getrandom 0.2`（starknet-crypto 链），**编译通过**。

### 1.2 `cargo check --target wasm32-unknown-unknown` 三变体：**全部 EXIT=0**

| feature 组合 | 结果 | 日志 |
|---|---|---|
| default（std，无 parallel/prover） | EXIT=0，26.6s | `logs/wasm_check_default.txt` |
| + `parallel`（rayon 1.12） | EXIT=0（**可编译**；运行时行为见 §3.4） | `logs/wasm_check_parallel.txt` |
| + `prover`（SimdBackend，portable_simd 等 nightly feature） | EXIT=0（**portable_simd 在 wasm32 可编译**） | `logs/wasm_check_prover.txt` |

即：**编译期没有 rayon/线程/JIT 类硬阻塞**。

### 1.3 发现的硬阻塞：Poseidon252 被 cfg 门排除（NO-GO 证据 #1）

`stwo-2.3.0/src/core/channel/mod.rs` 与 `src/core/vcs_lifted/mod.rs`：

```rust
#[cfg(not(target_arch = "wasm32"))]
mod poseidon252;
#[cfg(not(target_arch = "wasm32"))]
pub use poseidon252::Poseidon252Channel;
```

最小复现（`dep-check/src/lib.rs` 引用 `Poseidon252Channel`）：

```text
error[E0433]: cannot find `Poseidon252Channel` in `channel`
note: found an item that was configured out
  --> .../stwo-2.3.0/src/core/channel/mod.rs:11:22
```
（`logs/wasm_poseidon_compile_error.txt`；同目标 native check EXIT=0）

该模块内部只用 `starknet_crypto::{poseidon_hash, poseidon_permute_comp}`（纯 Rust，其依赖在 wasm32 本可编译），**门是上游的选择而非技术依赖**——解除它是一个小补丁（cfg 改 feature 门）。

**含义**：canonical 证明（`StarkProof<Poseidon252MerkleHasher>`）在浏览器端用 stwo 2.3 验证 = 现状不可编译。Fiat–Shamir 信道绑定哈希器，换任何其他哈希器都无法验证现有证明。

### 1.4 附带发现

- **stable Rust 可编译验证器路径**（`cargo +stable check --target wasm32-unknown-unknown` EXIT=0，`logs/wasm_check_stable.txt`）；nightly 仅 `prover` feature 需要（`iter_array_chunks/portable_simd/slice_ptr_get`）。wasm 验证器不必绑 nightly。
- **运行期陷阱（探针亲自踩到）**：`std::time::Instant::now()` 在 wasm32-unknown-unknown 直接 panic（无时钟 syscall）——接入 wasm 时验证路径内不能有计时/时间调用（`stwo` 核心验证路径本身没有）。

---

## 2. 步骤2：验证器路径编译进 wasm32 + JS 胶水：**通过**

产物（`stwo-wasm-probe/wasm/`，release，opt-level=3，codegen-units=1）：

| 变体 | 体积 | 内容 |
|---|---|---|
| `probe_verifier_only.wasm` | **325,064 B** | 纯验证路径（无 prover/parallel） |
| `probe_prover_feature.wasm` | 596,060 B | +SimdBackend（canonical verify 的 scope 重建需要） |
| `probe_prover_parallel.wasm` | 761,930 B | +rayon（canonical 栈实际 feature 组合） |

- JS 胶水：**手写 C ABI**（`probe_alloc/probe_free/probe_verify/probe_last_error`），bincode 序列化 `ProbeCase`，node 直接 `WebAssembly.instantiate`，**未引入 wasm-bindgen 依赖**（省掉 wasm-bindgen-cli 工具链）。
- **正确性证据**：每个 case 的真证明在 wasm 内 rc=0 通过；对 case 字节翻转 1 bit 后 rc=-2 拒绝（`tamper_test: rc=-2 (rejected, ok)`，所有 case 均拒绝）。证明 wasm 内跑的是完整 FRI+Merkle+约束验证，非占位。
- canonical verify 特有的 **scope 重建承诺**（`verify_canonical_stark` L9453-9474 用 `SimdBackend` 重建 scope 树并比对 `commitments[0]`）也单独编译进了 wasm 并实测（§3.3）——这一步同样需要 `prover` feature，wasm32 编译通过。

---

## 3. 步骤3：延迟实测

基准口径：release 构建、预热后 N=25（canonical 真值对照 N=20）、最近秩分位（与 `poker-appchain-texasair/tests/perf_baseline.rs` 同口径）。机器：Apple M3 Pro。**加粗**为关键数字。

### 3.1 列数敏感度扫描（Blake2s，log_size=8，wasm / native 成对）

| 列数合计（tree0+tree1+tree2） | native p50 (ms) | wasm p50 (ms) | wasm/native |
|---|---|---|---|
| 177（1+60+116，sanity） | 0.477 | 0.649 | 1.36× |
| 3116（1000+2000+116） | 2.673 | 3.487 | 1.30× |
| **7435（1927+5392+116，canonical 同宽）** | **6.729** | **7.686** | **1.14×** |

- 线性拟合（wasm）：斜率 ≈ **0.97 µs/列**，截距 ≈ 0.48ms → 验证成本随列数近线性，外推可信。
- log_size 10（canonical 同宽）：wasm p50 8.071ms（native 6.861ms）——**域大小几乎不影响验证延迟**（n_queries 固定 30，Merkle 深度 +2 可忽略）。
- **M31/FRI 数学在 wasm32 上只慢 1.14–1.36×**（Rust wasm32 代码生成质量好）。

原始输出：`logs/bench_native_blake2s_*.txt`、`logs/wasm_blake2s_*.txt`（终版 `*_final.txt` 用最终源码重建复测，p50 7.870/7.670ms，与首测一致）。

### 3.2 哈希器对比（native，canonical 同宽，Poseidon vs Blake2s）

| case（canonical 同宽） | native verify p50 (ms) |
|---|---|
| Blake2s log8 / log10 | 6.729 / 6.861 |
| **Poseidon252 log8 / log10** | **110.472 / 119.263** |

Poseidon 承诺验证 ≈ **16.4×** Blake2s（Merkle 路径哈希 + FRI 逐层验证都是哈希主导）。

### 3.3 canonical verify 特有开销：scope 重建承诺

对齐 `verify_canonical_stark` 的 `simd_twiddles + CommitmentSchemeProver tree_builder + commit`（1927 列）：

| 平台/哈希 | log8 | log10 |
|---|---|---|
| native Blake2s | 7.234 ms | 28.810 ms |
| **wasm Blake2s（单线程 SimdBackend）** | **24.268 ms p50** | **90.626 ms p50** |
| native Poseidon | 411.099 ms | 1626.769 ms |

wasm/native ≈ 3.4×（`portable_simd` 在 wasm32 无硬件 SIMD，FFT/承诺路径劣化比纯 FRI 验证大）。

### 3.4 parallel（rayon）运行时行为：**无 panic，优雅退化**

`logs/wasm_parallel_runtime_check.txt`：parallel 变体在 node 里调用 scope commit（log8×1927 与 log10×1927/5392）全部 rc=0；耗时与单线程变体持平（22.68 vs 21.95 ms p50）——rayon 在 wasm32-unknown-unknown 上把并行任务就地执行，**没有线程 panic**。注：这是在本次工作负载下的经验结论；更重的 `prove_values` 并行分支未逐一验证。

### 3.5 canonical 真值对照（poker-appchain-texasair `perf_baseline`，本机实跑）

```
PERF m4_acc_1 stats prove_p50_ms=491.7 prove_p95_ms=545.9 prove_p99_ms=565.5
     verify_p50_ms=188.7 verify_p95_ms=209.2 verify_p99_ms=230.0
     ready_p50_ms=693.0 ... gate_p95_ms=3000 verdict=PASS
```
（`verify_canonical_tagged_proof` 端到端，含 1.19MB bincode 反序列化 + archive 校验 + scope 重建 + STARK 验证；archive 1,187,652 B，与探针同规模 case 的 proof_bytes 1.09–1.19MB 吻合，交叉印证列数校准正确。）

**注意**：native canonical 总 verify p50 = 188.7ms，其中 scope 重建贡献比探针独立测量（411ms）小——canonical 侧复用进程级 twiddle 缓存与 memory pool，且 scope 构建路径更精简。因此**估算 wasm Poseidon 延迟时以 188.7ms 真值为基线**（§5.3），而非探针分解值之和。

---

## 4. 步骤4：canonical AIR 量级外推（M4-ACC-5 单手 ≤500ms）

**实测部分（可信）**：canonical 形状（列数 7435、log8、pow10/q30/blowup1）在 **Blake2s** 下：wasm STARK 验证 **7.686ms p50** + wasm scope 重建 **24.268ms** + 反序列化/校验 ~2–5ms（1.12MB 输入拷贝+bincode）≈ **总计 ~35ms，≈ 500ms 预算的 7%**。列数线性度已验证（§3.1），即使 canonical 列数再翻倍仍在 60ms 量级。

**估算部分（明确标注：估算）**：若保持 **Poseidon252** 且上游解除 wasm32 cfg 门：

- 基线：native canonical verify p50 = 188.7ms（真实值，§3.5）。
- wasm 放大系数分解：纯域数学部分实测 1.14–1.36×（§3.1）；FFT/承诺类 `portable_simd` 工作实测 3.4×（§3.3）；Poseidon 排列（`starknet-crypto` 的 felt252 大整数运算，wasm32 上 u64/128 位运算为软件模拟）**无实测值**（编译被门），参照同类按 **2–5×** 取区间。
- 加权估算：188.7ms 中 STARK 验证主体（哈希主导）×(2–5×)，其余 ×(1.2–3.4×) →

  **wasm Poseidon canonical verify ≈ 0.4 – 0.8s（估算区间，中位偏上）**，vs 预算 500ms：**marginal，不保证达标**；且该估算前提是上游先解除 cfg 门。

---

## 5. 错误清单 / NO-GO 证据汇总（按步骤）

| # | 发现 | 影响 | 等级 |
|---|---|---|---|
| 1 | `Poseidon252Channel`/`Poseidon252MerkleChannel` 被 `#[cfg(not(target_arch="wasm32"))]` 排除（E0433 复现，§1.3） | 现有 canonical 证明无法在浏览器验证（现状硬阻塞） | **阻断** |
| 2 | 若保持 Poseidon：wasm 延迟估算 0.4–0.8s（§4），可能超 500ms | 验收风险 | 高（估算） |
| 3 | `std::time::Instant` 在 wasm32 panic（探针实测触发） | 验证路径不得含时钟调用；stwo 核心验证路径无此调用 | 中（接入注意项） |
| 4 | `parallel` feature 的 rayon 分支在 wasm 上未 panic、就地执行（§3.4） | 低；但"rayon 可用"不能想当然（未验证全部并行分支） | 低 |
| 5 | stwo `prover` feature 需要 nightly（`portable_simd` 等）——但 canonical verify 的 scope 重建需要该 feature | wasm 验证器要么等上游把 scope 重建挪出 prover 门，要么 wasm 侧绑 nightly | 中 |
| 6 | rayon/std::thread/getrandom/JIT：**均不构成阻塞**（§1.1–1.2、§3.4） | — | 无 |

## 6. 建议

**推荐路径 B（探针已完整验证）**：canonical 栈承诺哈希迁到 **Blake2s**（`Blake2sMerkleChannel`，stwo 2.3 原生全平台支持），prover/verifier 原子切换：

1. `poker_texas_air`：`CommitmentSchemeProver/Verifier/Channel` 泛型从 `Poseidon252*` 换 `Blake2s*`（探针证明两端 API 完全对称，机械替换）；归档格式版本号 +1，旧归档保留 Poseidon 验证路径或标记弃用。
2. wasm 侧：新增 `verify-only` crate（可参照 `stwo-wasm-probe/src/lib.rs` 的 C ABI 模式，无 wasm-bindgen 依赖），产物 325KB。
3. **工作量估算**：哈希替换+回归 2–3 人日（sign/serialize 契约不变，主要是泛型替换 + 全量测试 + 归档迁移策略）；wasm 验证 crate + node/浏览器接入 2–3 人日；合计 **~1 周**。性能预期：浏览器单手验证 ~35ms（预算的 7%），另有把 scope 重建改为预计算/复用（canonical 已有 twiddle 缓存模式可搬）进一步压缩的空间。
4. 附带收益：出证也提速（同机 prove 491.7ms → 61ms，实测 §gen_all_cases），M4-ACC-1（3s 门）余量同步放大。

**备选路径 A（保 Poseidon）**：给 starkware-libs/stwo 提 issue，建议把 `cfg(not(target_arch = "wasm32"))` 改为显式 feature 门（如 `poseidon`），理由：其依赖 `starknet-crypto 0.6.2` 在 wasm32-unknown-unknown 本身可编译（本探针 §1.1/1.2 实测），排除属预防性而非必要性。等上游发布 + 本地按 §4 估算做真机复测，通过后再评估接入。**在此之前 M4-ACC-5 按 blocked-by 上游处理。**

**下一步（无论路径）**：浏览器（Chrome for Testing，与 extension 测试同环境）复测 wasm（node 与 V8 同引擎，预期差异小）；补一条"篡改样本在浏览器拒绝"的端到端用例作为验收件。

---

## 附：探针工件索引

```
stwo-wasm-probe/
├── src/lib.rs            # demo AIR（三树+LogUp+双哈希器）+ verify + wasm C ABI
├── src/bin/gen_proof.rs  # 原生出证（nightly+prover）
├── src/bin/bench_native.rs
├── dep-check/            # 步骤1 最小依赖工程
├── tools/eval_consts.py  # canonical 列数 const 链机械求值
├── wasm/verify.mjs       # node 基准（含篡改拒绝用例）
├── wasm/scope_commit.mjs # wasm scope 重建基准
├── wasm/*.wasm           # 三个构建变体（325KB/596KB/762KB）
├── cases/*.bin           # 7 个证明用例
└── logs/*.txt            # 全部原始输出（本文所有实测数字出处）
```

*报告日期：2026-09-13。stwo 版本：crates.io `stwo` 2.3.0（constraint-framework 2.3.0）。探针未改动 zchain 主 workspace 与 poker_texas_air（只读），未 git commit。*
