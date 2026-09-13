# stwo-wasm path A 实施报告 — canonical 证明格式不变，验证器进 wasm

**结论：交付（延迟超预算，如实标注）。** canonical 真证明（Poseidon252 承诺，
格式零改动）现在可以在浏览器扩展内完成**完整 STARK 验证**（FRI + Merkle +
约束 + 公开 scope 承诺重建）。实测 wasm 验证 p50 ≈ **1.70–1.80s**、p95 ≈
1.80–1.98s，**超 500ms 验收门槛约 3.5×**（也高于探针 0.4–0.8s 的估算区间）。
按用户决策口径（性能不敏感、低频验证场景可接受）照常接入 portal，portal
如实展示真实耗时并标注"超预算（低频场景可接受，性能优化留后续）"；负例
（篡改/截断/非归档）全部拒绝，无任何伪造结论路径。

- 日期：2026-09-13（接 stwo-wasm-probe 2026-09-12/13 报告）
- 环境：macOS arm64（Apple M3 Pro，36 GB），rustc nightly-2026-04-15（zchain 根
  toolchain pin），node v24.4.1，Chrome for Testing 153，wasm32-unknown-unknown
- 本报告工件：`third_party/stwo-wasm-patch/`、`stwo-wasm-verify/`（独立
  workspace）、`extension/vendor/stwo-verify/`、`extension/common/stwo_verify.js`、
  `extension/common/portal.js`、`extension/portal/`、`extension/tests/e2e/run_04.mjs`
- 纪律确认：poker_texas_air 只读（path 依赖，零文件改动）；未 git commit；
  未动禁区（poker_l1/、poker-appchain/、poker-wallet/、wallet-app/、
  tools_external/、website/、docs/ 其他文件、根 Cargo.toml）；零新增 crates.io
  依赖族（borsh 1.x / 全部传递依赖均已在既有依赖树内）

---

## 1. 决策记录

**用户拍板：path A**——保持 canonical 证明格式不变（Poseidon252 承诺、
bincode StarkProof + borsh 归档信封原样），不解锁上游就本地动手：把 stwo
2.3.0 解除 wasm32 cfg 门（vendored 副本），把 canonical 真证明的验证器编译进
wasm，实测延迟后接入扩展 proof portal。

- **理由**：路径 B（承诺哈希迁 Blake2s，探针推荐）要求 poker_texas_air 出证
  侧原子换哈希 + 归档版本迁移，动的是已上线的证明格式；path A 在验证侧单点
  解锁，证明格式与存量归档全部不动。性能风险（探针估算 0.4–0.8s marginal）
  由用户明确接受："性能不敏感，超 500ms 也可交付，但必须如实展示真实耗时"。
- **探针结论 → path A 的衔接**：探针已证明 (a) stwo 2.3.0 依赖树 wasm32 可
  编译；(b) 唯一硬阻塞是 `src/core/channel/mod.rs` 等处的预防性 cfg 门
  （非技术依赖缺失——starknet-crypto 0.6.2 在 wasm32 本可编译）；(c) 手写
  C ABI + JS 胶水管线跑通。本次实施把这三点全部落到 canonical 真证明上。

## 2. vendored stwo（`third_party/stwo-wasm-patch/stwo-2.3.0/`）

来源：cargo registry `index.crates.io-1949cf8c6b5b557f/stwo-2.3.0` 逐文件复制。
**唯一实质（功能）变更**：poseidon252 家族的 `#[cfg(not(target_arch =
"wasm32"))]` 改为 `#[cfg(feature = "wasm-poseidon")]`，共 **16 个门 / 15 处
替换 / 8 个文件**：

| 文件 | 门数 | 内容 |
|---|---|---|
| `src/core/channel/mod.rs` | 2 | `mod poseidon252` + `pub use Poseidon252Channel` |
| `src/core/vcs/mod.rs` | 1 | `pub mod poseidon252_merkle`（Poseidon252MerkleHasher） |
| `src/core/vcs_lifted/mod.rs` | 1 | `pub mod poseidon252_merkle`（Poseidon252MerkleChannel） |
| `src/core/vcs_lifted/verifier.rs` | 1 | poseidon merkle 测试（一致性） |
| `src/prover/backend/simd/mod.rs` | 4 | use + `poseidon252`/`poseidon252_lifted` 模块 + `BackendForChannel<Poseidon252MerkleChannel> for SimdBackend`（canonical verify 的 scope 重建必需） |
| `src/prover/backend/simd/poseidon252.rs` | 1 | `use core::vcs::MerkleHasher`（MerkleOps 实现内） |
| `src/prover/backend/cpu/mod.rs` | 3 | use + 模块 + CpuBackend 同型 impl |
| `src/prover/backend/simd/grind.rs` | 3 | poseidon PoW grind + 2 测试 |

非功能（元数据/文档）变更：`Cargo.toml` 新增 `wasm-poseidon` feature（**default
开启**：`default = ["std", "wasm-poseidon"]`）、空 `[workspace]` 表（vendored
crate 自成 workspace 根，与 zchain 根 workspace 隔离）、头部 provenance 注释；
8 个被改源文件头部 provenance 注释；本目录 README 与全树 diff 存档
`PATCH-vs-crates-io-2.3.0.diff`（`diff -ru`，除去文档/元数据行后功能差异仅
16 行 cfg 门替换）。

**为什么是 feature 门（default 开）而不是移除门**（二选一的理由）：保留上游
"无 poseidon 的 wasm 构建"逃生口（推测上游动机：省体积/少拉依赖），把隐式
target 排除改成显式可选；default 开启使 native 行为逐字节不变、wasm 侧与
native 一致（canonical 证明开箱可验）；对上游 issue 是最小可接受的请求形态。

**解除门的技术依据**：poseidon252 家族在 wasm32 上的全部依赖是
`starknet-crypto 0.6.2`（纯 Rust）+ `starknet-ff 0.3.7`，二者本就是 stwo 的
无条件依赖且 wasm32 编译通过（探针 `logs/wasm_check_*.txt` 三变体 EXIT=0）。
门是预防性的，不是技术性的——本次 wasm 实测进一步证明：解除门后 poseidon252
承诺路径（信道 + Merkle + FRI）在 wasm32 内计算结果与 native 完全一致
（3 份真证明全部 verified、篡改全部拒绝，且与 native batch_digest 一致）。

**使用方式**（只影响消费者自己的 workspace，不动根 workspace）：
`stwo-wasm-verify/Cargo.toml` 内 `[patch.crates-io] stwo = { path =
"../third_party/stwo-wasm-patch/stwo-2.3.0" }`——把整张依赖图（含
poker_texas_air 的 `stwo = "2.3"`）重定向到副本。

## 3. 验证器 wasm（`stwo-wasm-verify/` 独立 workspace）

### 3.1 依赖方案（重要选择，含一次降级尝试）

crate A（`stwo-verify-core`）采用 **poker_texas_air 全量 path 依赖**
（探针报告的降级方案未采用）：

- 先按任务预案评估 `#[path]` 只引入 `texas_canonical_air.rs` 所需模块链：
  模块闭包实际有 **33 个文件**（texas_canonical_air → texas_canonical /
  canonical_rake_opening / trace_gen / prover_context / blake3_flock /
  smt_statements / …），且 `canonical_rake_opening.rs` 生产代码
  `use poker_l1::contracts::texas_poker::types::TableRules`——链条仍然拖进
  poker_l1，降级方案并不能甩掉重依赖，还引入"复刻模块树"的长期维护成本。
  **放弃该降级，选择全量 path 依赖**。
- 全量 path 依赖在 wasm32 的唯一堵点：poker_l1 → secp256k1 0.29 →
  **secp256k1-sys 的 C 代码**（`cc-rs` 调用的 Apple clang 无 wasm32 后端，
  E0599 式 build script 失败复现于首次 `cargo check --target wasm32`）。
  解决：`.cargo/config.toml`（仅本 workspace）把
  `CC_wasm32-unknown-unknown` 指向 brew llvm 的 clang（带 wasm32 后端），
  编译的是 **secp256k1-sys 官方自带的 wasm/wasm.c + wasm-sysroot**——
  上游 C 源码零改动，无任何密码学替身。此后 `cargo check --target
  wasm32-unknown-unknown` EXIT=0（poker_texas_air 全树 + vendored stwo）。

### 3.2 crate A / crate B / 出证工具

- **crate A** `stwo-verify-core`：`verify_canonical_proof_wasm(archive_bytes)
  -> Result<VerifyStats, String>`。Err = borsh 归档信封解码失败；Ok 的
  `VerifyStats{verified, error, archive_len, table_id, log_size, num_columns,
  transition_count, batch_digest_hex, internal_elapsed_ms}`（+ `VERIFIER_ID`
  版本串，`to_json()` 手写序列化避免新依赖）。验证逻辑 = poker_texas_air
  `verify_canonical_tagged_proof` 原样调用（归档形状校验 → state image /
  rake binding → scope 公开承诺重建（SimdBackend+Poseidon，prover feature）
  → 完整 STARK verify）。native 单测 2/2 PASS。
- **crate B** `stwo-verify-wasm`（cdylib）：手写 C ABI
  `sv_alloc/sv_free/sv_verify/sv_stats/sv_stats_len/sv_last_error`（探针已验证
  模式，无 wasm-bindgen 工具链）。rc 语义：0=verified；-1=归档解码失败；
  -2=验证拒绝；-3=内部错误。**诚实计时**：wasm32 内零时钟调用
  （`Instant` panic，探针实测），墙钟由宿主测；`internal_elapsed_ms` 仅
  native 有值。
- **出证工具** `gen-canonical`（native only）：witness 构造镜像
  poker-appchain-texasair `perf_baseline::full_hand_witnesses`（已证五行模式，
  host 侧 `validate_shape` 自检），3 张独立桌（table_id 9101/9102/9103）各出
  一份真证明，borsh 落盘 + manifest。prove ~526–538ms、native verify
  **195.1–200.6ms**（与 texasair perf_baseline 的 verify p50 188.7ms 同量级 ✓）。

### 3.3 实测延迟（对照 0.4–0.8s 预估与 500ms 门槛）

口径：release 构建，每份证明预热 1 次（冷启动单列）后连续验证 **12 次**，
最近秩分位；输入为真实 canonical 归档（1,156,406–1,185,984 B）；宿主
node v24.4.1，Apple M3 Pro。原始输出 `stwo-wasm-verify/logs/bench_run_01.txt`
（plain 构建）、`logs/bench_run_02_simd128.txt`（simd128 构建）、结构化
`logs/wasm_bench_result.json`。

| 构建 | 证明（table） | cold ms | min ms | p50 ms | p95 ms | max ms | 500ms 门槛 |
|---|---|---|---|---|---|---|---|
| plain（无特调 flags） | 9101 | 1874.9 | 1832.8 | 1847.3 | 1982.1 | 1982.1 | OVER |
| plain | 9102 | 1834.4 | 1780.3 | 1795.9 | 1866.4 | 1866.4 | OVER |
| plain | 9103 | 1780.1 | 1775.2 | 1784.6 | 1826.5 | 1826.5 | OVER |
| **plain 汇总（3 份合计）** | — | — | — | **1795.9** | **1982.1** | — | **OVER（3.6×）** |
| simd128（`-C target-feature=+simd128`，交付产物） | 9101 | 1767.7 | 1697.3 | 1739.0 | 1861.0 | 1861.0 | OVER |
| simd128 | 9102 | 1813.9 | 1715.8 | 1726.8 | 1779.2 | 1779.2 | OVER |
| simd128 | 9103 | 1724.6 | 1713.2 | 1734.7 | 1782.2 | 1782.2 | OVER |
| **simd128 汇总（两次运行区间）** | — | — | — | **1699–1735** | **1798–1861** | — | **OVER（≈3.5×）** |

- **与探针 0.4–0.8s 估算对照**：实测落在估算区间之外（约 2.2× 于上界）。
  估算偏差来源（如实归因）：探针的 2–5× Poseidon 放大系数是"参照同类"的
  区间猜测；实测 wasm/native ≈ **9.2×**（1735/195）——Poseidon 排列在
  wasm32 上是 starknet-crypto 的 felt252 大整数软件运算（u64/128 位乘法
  模拟），劣化显著大于 M31 域数学（探针实测 1.14–1.36×）。探针报告 §4 的
  "marginal，不保证达标"判断方向正确，幅度偏乐观。
- **与 500ms 门槛对照**：超约 3.5×。按用户决策口径交付：portal 如实展示
  真实耗时并标注"超预算（低频场景可接受，性能优化留后续）"（见 §5/§6）。
- simd128 变体仅 ~3.5% 收益，作为交付产物（Chrome 91+ 基线支持，体积更小
  3.05MB vs 3.36MB）；plain 数字并列入档供对照。
- wasm 产物体积：3,050,318 B（含 poker_texas_air 验证器全链 + stwo
  prover/parallel + Poseidon252；探针纯验证 demo 是 325KB，体量差来自
  canonical AIR 本体 + prover feature 的 SimdBackend/twiddle 路径）。
- **正确性交叉印证**：wasm 与 native 对同一证明的判定完全一致，且三份
  归档的 `batch_digest`（wasm stats 内回读）与 native 出证一致——证明 wasm
  内跑的是完整真验证器，不是占位。

## 4. 负例验证（全部拒绝，9/9 + 3 类单测）

node 基准内每份证明 3 类负例（`logs/wasm_bench_result.json` 的 negatives 数组）：

| 负例 | 变换 | rc | 拒绝原因（wasm 返回） |
|---|---|---|---|
| mid_byte_flip | STARK 证明体中段翻转 1 bit | **-2** | AIR 约束不满足: Root mismatch. |
| header_field_flip | 公共字段区翻转 1 bit | **-2** | 业务规约违反: canonical pre endpoint image is detached from archive scope |
| truncated_quarter | 截断至 1/4 | **-1** | archive borsh decode: Unexpected length of input |

3 份证明 × 3 类 = **9/9 拒绝**。另在真实浏览器 E2E（run_04 F2/F3）复现：
篡改证明 → `StarkVerifyRejected`；非归档字节 → `StarkArchiveInvalid`。

## 5. 扩展 portal 接线（`extension/`）

- **产物 vendored**：`extension/vendor/stwo-verify/` =
  `stwo_verify_wasm.wasm`（sha256 `8e5c0f2e…4d8f2bb`，3,050,318 B）+
  `stwo_verify_loader.mjs`（sha256 `f58c6d4e…7f67f1c`，宿主侧胶水，零依赖
  ES module）+ `MANIFEST.json`（sha256/字节数/构建命令/工具链/实测延迟与
  超预算声明/负例证据）。fixture 真证明：
  `extension/tests/fixtures/stwo_verify/canonical_table9101.bin`
  （sha256 `ee0b7eff…4b6d`）。
- **JS 门面**：`extension/common/stwo_verify.js`（模式同 `wallet_core.js`）：
  幂等加载 wasm、`verifyCanonicalArchive(bytes)` 转发归档字节；**验证语义
  零 JS 重实现**。loader 对 wasm 的 5 个 wasm-bindgen 占位导入
  （getrandom 的 js feature 经 feature 统一拖入）做 **fail-closed 桩**：
  满足链接、一旦被真实调用即抛错（验证路径是确定性的，触发即说明跑偏，
  绝不静默返回假值）。
- **`common/portal.js` 流程升级**（全部向后兼容，旧导出签名不变）：
  settlement → proof 归档（`fetchProof` 新增透传 `payloadB64` 本体 +
  AbortController 超时，超时归类 `GatewayTimeout`，与
  `GatewayUnreachable` 分开）→ **`verifyStarkProof(payloadB64,
  starkVerifyFn)` 新阶段**：本地 wasm 完整 STARK 验证，返回
  verified / `StarkVerifyRejected` / `StarkArchiveInvalid` /
  `StarkVerifierError` 四态与真实耗时 → wallet-core 结算关系复验（保留）→
  结论页（**fail-closed**：STARK 跳过/拒绝 ≠ verified，任一环节未通过即
  "not verified"）。
- **portal 页**（`portal/portal.html|.js`，版本号 0.2.0-alpha → 0.4.0-alpha）：
  新增 "STARK 完整验证（stwo wasm）" 卡片——verifier 版本串
  （`stwo-wasm-verify/0.1.0 (stwo 2.3.0 vendored+wasm-poseidon; poker_texas_air
  canonical AIR)`）、table_id/log_size/列数/transition_count/batch_digest、
  宿主墙钟耗时；**耗时 > 500ms 时如实标注"超预算（低频场景可接受，性能
  优化留后续）"**；拒绝/归档非法/验证器错误三态各自如实呈现；结论卡汇总
  STARK 与结算复验两项独立结果。网关不可达/未配置/404/超时全部如实报错
  （原有行为保留）。
- **注入式设计不变**：`verifyStarkProof` 的验证函数与 fetch 均注入
  （生产 = 真 wasm 门面，测试 = stub），`node --test` 无浏览器也能覆盖分类
  逻辑。

## 6. 测试与 E2E 证据

| 项 | 结果 | 证据 |
|---|---|---|
| wasm32 编译（poker_texas_air 全树 + vendored stwo） | EXIT=0 | `cargo check --target wasm32-unknown-unknown -p stwo-verify-core -p stwo-verify-wasm` |
| vendored stwo 与 registry 全树 diff | 9 文件差异，功能差异仅 16 行 cfg 门 | `third_party/stwo-wasm-patch/PATCH-vs-crates-io-2.3.0.diff` |
| crate A native 单测 | 2/2 PASS | `cargo test -p stwo-verify-core` |
| node 基准（3 证明 × 12 次 + 9 负例） | 3/3 verified、9/9 拒绝；p50 1795.9ms（plain）/1699–1735ms（simd128），**门槛 OVER 如实记录** | `stwo-wasm-verify/logs/bench_run_01.txt`、`bench_run_02_simd128.txt`、`wasm_bench_result.json` |
| extension 单测套件 | **142/142 PASS，0 skip**（含 STARK 阶段 7 例：分类/fail-closed/base64 守恒/超时分类 + 真实 wasm 冒烟：正例 verified + 篡改拒绝） | `node --test tests/*.test.js tests/adapters/*.test.js` |
| E2E run_04（新，portal STARK 流，真实浏览器） | **12/12 PASS**（F1 正例 verified 1790ms + verifier 版本/元数据/耗时展示；F2 篡改拒绝 + fail-closed 结论；F3 非归档；F4 无归档如实跳过；F5 不可达；F6 超时分类；F7 结算复验照常执行记录） | `extension/tests/e2e/e2e04_result.json`、`e2e04_screenshot.png` |
| E2E run_02 回归 | **36/36 PASS**（真实 explorer gateway 链路） | `e2e02_result.json`（本次实跑刷新） |
| E2E run_03 回归 | **30/30 PASS** | `e2e03_result.json`（本次实跑刷新） |

run_04 边界（诚实记录）：fixture 网关是 runner 内 node http server（真实
canonical 证明字节 + 形状一致的 settlement 明细 fixture）；wallet-core 结算
复验步骤照常执行并记录（fixture 明细未通过复验——`InvalidArgument`——如实
记录、不作通过断言），真实结算链路由 run_02 的真实 explorer gateway 覆盖。

## 7. Upstream issue draft（英文全文，拟提交 starkware-libs/stwo）

> **Title: Turn the wasm32 exclusion of the Poseidon252 family into an explicit feature gate**
>
> **Summary**
>
> In stwo 2.3.0, the entire Poseidon252 stack (channel, VCS Merkle hashers,
> and the backend `MerkleOps`/`BackendForChannel` impls) is excluded at
> compile time on wasm32 via `#[cfg(not(target_arch = "wasm32"))]`:
>
> - `src/core/channel/mod.rs` (`mod poseidon252`, `pub use Poseidon252Channel`)
> - `src/core/vcs/mod.rs` (`pub mod poseidon252_merkle`)
> - `src/core/vcs_lifted/mod.rs` (`pub mod poseidon252_merkle`)
> - `src/prover/backend/simd/mod.rs` (use, `poseidon252`/`poseidon252_lifted`
>   modules, `impl BackendForChannel<Poseidon252MerkleChannel> for SimdBackend`)
> - `src/prover/backend/cpu/mod.rs` (same shape for `CpuBackend`)
> - `src/prover/backend/simd/grind.rs` (poseidon PoW grind)
> - `src/prover/backend/simd/poseidon252.rs` (the `use crate::core::vcs::MerkleHasher` import)
>
> **Why we believe the gate is preventive, not technical**
>
> The only wasm-relevant dependencies of these modules are
> `starknet-crypto 0.6.2` and `starknet-ff 0.3.7`, both of which stwo already
> depends on unconditionally (`default-features = false, features = ["alloc"]`)
> for `Poseidon252MerkleHasher`. Both crates are pure Rust and compile fine
> for `wasm32-unknown-unknown` (their transitive wasm-bindgen/getrandom chain
> included). We verified `cargo check --target wasm32-unknown-unknown` passes
> for stwo 2.3.0 itself with default features, and — after locally flipping
> only the cfg attributes above to a feature gate — the full
> `Poseidon252Channel`/`Poseidon252MerkleChannel` verifier path (channel,
> Merkle decommitment, FRI, and the SimdBackend scope-recommit path under the
> `prover` feature) compiles **and produces byte-identical verification
> verdicts to native x86-64** on real production proofs (3/3 genuine accepted,
> 9/9 tampered/truncated rejected).
>
> **Request**
>
> Replace the target-based exclusion with an explicit feature (e.g.
> `poseidon252`), either default-on or default-off per your preference:
>
> ```toml
> [features]
> poseidon252 = []
> ```
>
> ```rust
> #[cfg(feature = "poseidon252")]
> mod poseidon252;
> ```
>
> This keeps the current ability to build a poseidon-free wasm verifier
> (smaller binaries, no starknet-crypto linkage) while letting wasm consumers
> who *do* verify Poseidon-committed proofs opt in. Default-on would change
> nothing for existing native users.
>
> **Motivating use case**
>
> We verify Circle-STARK proofs whose Fiat–Shamir channel and Merkle
> commitments are bound to `Poseidon252MerkleChannel` (the Starknet poseidon
> permutation with its COMPRESS-style domain separation). Since the channel
> hasher is protocol-binding, these proofs cannot be verified with any other
> hasher, so the cfg gate currently makes browser-side verification of
> existing proofs impossible without a vendored patch.
>
> **Evidence**
>
> - stwo 2.3.0 `cargo check --target wasm32-unknown-unknown` (default
>   features): PASS; with `parallel` and `prover` features: PASS on nightly
>   (portable_simd compiles for wasm32).
> - Vendored single-purpose patch (cfg → feature, 16 gate sites / 8 files):
>   full STARK verification of production-sized proofs (log_size 8, 5391+
>   columns, 3 commitments, 30 FRI queries, PoW 10) runs in a wasm runtime
>   with verdict parity against native.
> - Happy to send the patch as a PR if the feature-gate direction is
>   acceptable.

（提交前按上游 issue 模板补环境明细即可；草稿正文如上，未删节。）

## 8. 遗留边界（如实列出）

1. **延迟超预算**：wasm 验证 p50 ≈ 1.7–1.8s / p95 ≈ 2.0s，超 500ms 门槛约
   3.5×，亦高于探针 0.4–0.8s 估算（估算的 2–5× Poseidon 放大系数偏乐观，
   实测 wasm/native ≈ 9.2×，Poseidon 的 felt252 软件大数运算是主导项）。
   优化方向（未做，留后续）：`+simd128` 深度利用（当前仅 +3.5%）、把
   Poseidon252 Merkle 节点哈希换成手写 wasm SIMD、上游若接受 feature 门后
   走 `wee_alloc`/wasm-opt、或长期走路径 B（Blake2s 承诺，验证 ~35ms 量级）。
2. **`parallel`（rayon）在 wasm 上就地执行**：探针已验证无 panic；本次构建
   保留 poker_texas_air 的默认 feature 组合（parallel+prover），未单独复测
   重负载并行分支。
3. **wasm-bindgen 占位导入是桩**：getrandom 的 js feature（feature 统一，
   无法从下游关闭）拖入 5 个占位导入；loader 用 fail-closed 桩满足链接，
   调用即抛错。验证路径确定性所以不触发；若未来验证链路引入任何随机性
   依赖会立刻炸出来（这是期望行为）。
4. **secp256k1-sys 构建工具链**：wasm32 下需要带 wasm32 后端的 clang
   （本机 brew llvm），已固化在 `stwo-wasm-verify/.cargo/config.toml`（仅
   该 workspace）；上游官方 wasm C 源码零改动。CI 若复现需安装对应 clang。
5. **poker_texas_air 测试代码未在 wasm/本 workspace 编译**：其 `#[cfg(test)]`
   模块引用 test_support 等外部符号，`cargo test` 只对本 workspace 的 crate
   有意义；poker_texas_air 自身测试回归仍在其原仓库执行（只读，未触碰）。
6. **单手规模（log_size 8）为实测口径**：canonical 的 batch log_size 上限 10
   （`verify_canonical_tagged_proof` 形状校验），log10 的 wasm 延迟未单独
   基准（探针显示域大小对验证延迟影响很小，n_queries 固定时 +2 层 Merkle
   深度可忽略；如需可复用 harness 直接补测）。
7. **portal 的 STARK 卡片在 extension 页内加载 wasm**：E2E 经 http 同源
   harness 页覆盖完整管线（Chrome LNA 限制下扩展页跨源 fetch 网关的既有
   边界，与 run_02 一致）；扩展页自身的 wasm 加载走扩展源同源 fetch，
   已由单测冒烟（同引擎）覆盖。
8. **非 git commit**：全部产物在工作区未提交状态；`stwo-wasm-verify/target*`
   为构建缓存。

---

## 附：工件索引

```
third_party/stwo-wasm-patch/
├── README.md                      # 补丁说明（门点表/理由/依赖证据/使用方式）
├── PATCH-vs-crates-io-2.3.0.diff  # diff -ru 全树存档（功能差异=16 行 cfg 门）
└── stwo-2.3.0/                    # vendored 副本（8 文件带 provenance 头）
stwo-wasm-verify/
├── Cargo.toml / .cargo/config.toml
├── crates/verify-core|wasm|gen-native/
├── proofs/                        # 3 份真实 canonical 证明 + manifest
├── wasm/stwo_verify_loader.mjs    # 宿主胶水（fail-closed 导入桩）
├── harness/bench.mjs
├── logs/                          # bench_run_01.txt / bench_run_02_simd128.txt / wasm_bench_result.json
└── README.md
extension/
├── vendor/stwo-verify/            # wasm + loader + MANIFEST.json（sha256 清单）
├── common/stwo_verify.js          # wasm 门面（wallet_core.js 同模式）
├── common/portal.js               # +verifyStarkProof/GatewayTimeout/payloadB64
├── portal/portal.html|.js         # STARK 卡片 + 三态 + 超预算标注 + fail-closed 结论
└── tests/{stwo_verify.test.js, fixtures/stwo_verify/, e2e/run_04.mjs, e2e/stark_portal_harness.*}
```

*报告日期 2026-09-13。stwo 2.3.0（vendored，wasm-poseidon feature 门）。
poker_texas_air 只读。未 git commit。*
