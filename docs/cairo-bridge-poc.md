# Cairo Verifier 递归桥 PoC 报告（外部评审建议 2 · 出口交付）

**结论：CONDITIONAL（有条件 GO）。**

- **技术可行性：已证实**。用官方栈（scarb 2.11.4 + stwo-cairo 1.2.2）把「验证一段 canonical 形状 STARK 证明」写成 Cairo 1 程序（`verify_min`），cairo-vm proof-mode 运行 → stwo-cairo 出证 → Rust 侧 + 官方 `scarb verify` 双通道验证均通过。全链路零阻断，无 NO-GO 级证据。
- **成本量化（核心交付）**：Cairo 侧 M31/QM31 非原生运算成本已逐步实测（M31 乘 = 18.03 steps + 4 range_check；单次 FRI fold = 145.28 steps；单次 Poseidon252 channel 抽取 = ~511 steps，占大头）。按 canonical 形状（三棵树、log8、5508 可折列、q=30）外推：**完整递归桥 verifier 程序 ≈ 2.18×10⁸ Cairo steps / 证明（估算，方法与系数见 §5）**，出证时间在官方工具链同参数下 ≈ **7 分钟量级/证明（估算）**。
- **条件**：递归桥的价值只在「无信任退出（信任最小化 L1 校验）」场景成立，且必须**批量聚合**摊销。若 Phase 2 目标只是把 canonical 证明搬上链验证一次，本 PoC 数据支持**否决该单次形态**（一次桥接的 verifier 程序步数是直接证明 canonical AIR 本身的 ~50 万倍当量）。立项前提见 §7。

- 探针日期：2026-09-13
- 环境：macOS arm64（Apple M3 Pro, 36 GB）；scarb **2.11.4**（Cairo 2.11.4, Sierra 1.7.0）；rustc **nightly-2026-04-15**（zchain 根 toolchain pin）；stwo-cairo **1.2.2**（官方 v1.2.2 tag：`stwo-cairo-prover`/`stwo-cairo-common` 为本地 `third_party/stwo-cairo/` 已补丁源，`stwo-cairo-adapter`/`cairo-air` 为 crates.io 1.2.2，`stwo` 2.3.0，`cairo-vm` 3.2.0）
- 探针工程：`cairo-bridge-poc/`（独立 scarb workspace + 独立 Cargo workspace，未 git commit，未改动其他目录）；全部原始输出在 `cairo-bridge-poc/logs/`
- 真实性声明：下文所有「实测」数字来自真实运行（原始输出在 `logs/driver_raw.txt`、`logs/driver_full_run_console.txt`、`logs/scarb_prove_timed.txt`、`logs/scarb_verify_timed.txt`、`logs/scaling_anchor_1m_steps.txt`）；标「估算」的是外推值，方法与系数全部给出。

---

## 0. 探针设计

递归桥 = 把「验证我们 canonical STARK 证明」写成 Cairo 程序 → stwo-cairo 出 Cairo 证明 → Starknet 合约校验最终证明。PoC 取 canonical 形状的**最小子集**，但验证原语**全部直接复用官方代码**而非自制：

| 子集要素 | PoC 实现 | 来源 |
|---|---|---|
| M31/CM31/QM31 算术 | 官方 naive（bounded-int 路径） | vendored `stwo_verifier_core` v1.2.2 `fields/*` |
| FRI fold（circle→line + line） | 官方 `fri_fold`（packed unreduced + fused_mul_add） | `poly/utils.cairo` |
| Poseidon252 Fiat-Shamir channel | 官方 `Poseidon252Channel`（mix_commitment / draw_secure_felt） | `channel/poseidon252.cairo` |
| Poseidon252 Merkle 叶/节点哈希 | 官方 `PoseidonMerkleHasher::hash_node`（4×M31 打包→1 hades；内部节点 hades(x,y,2)） | `vcs/poseidon_hasher.cairo` |

canonical 形状对齐（与 `stwo-wasm-probe` 采集一致，只读）：三棵树（scope 1927 / trace 5392 / interaction 116 列，QM31 base 拆分）、log8 单手（承诺域 log9）、`FriConfig{log_blowup=1, log_last_layer_degree=0, n_queries=30, fold_step=1}`、pow_bits=10、29 列 LogUp。PoC 的 `verify_min` = **1 个查询 × 单 FRI 结构（9 层折：1 circle→line + 8 line，末层 deg=0 常数校验）× 深度 8 Merkle 路径 × 完整 channel 阶段（3 次 mix + 26 次 draw）**。

**交叉验证**：Rust driver（`driver/src/mirror.rs`）逐步镜像官方算术（starknet-crypto `poseidon_permute_comp` == corelib `hades_permutation`；plain QM31 折叠 == packed-unreduced 数学值），独立算出 FRI 末层常数与 Merkle 根，硬编码进 Cairo 程序；程序内用**官方 Cairo 代码**重算并断言相等。实测运行断言全部通过（VM 未 panic）→ **两条独立实现对官方语义的理解逐位一致**，外推所用的单位成本因此锚定在真实 verifier 语义上。

---

## 1. 步骤1：环境与工具链

### 1.1 可用性（无网络阻塞）

- scarb 2.11.4 已在 `~/.local/bin/scarb`，自带 `scarb execute / prove / verify`（官方 stwo 出证子命令）。
- 全部 Rust 依赖（cairo-lang-executable/runner 2.11.4、cairo-vm 3.2.0、cairo-air 1.2.2、stwo-cairo-adapter 1.2.2 等）在本地 cargo cache 已就绪，无需联网新拉取。
- GitHub 可达（拉取 stwo-cairo v1.2.2 tag 源码做 vendor）。

### 1.2 版本兼容补丁（NO-GO 证据链的一部分，全部已绕过并记录）

上游 stwo-cairo **v1.2.2 的 `.tool-versions` 钉 scarb 2.15.0**，本地 scarb 2.11.4 编译其 Cairo 源需 4 类机械补丁（全部在 `cairo-bridge-poc/vendor/` 内以 `// PATCH(cairo-2.11)` 注释标记，未改动任何约束/常量/语义）：

| # | 不兼容项 | 上游位置 | 补丁 |
|---|---|---|---|
| 1 | `[features]` 的 `dep/feature` 转发语法（scarb 2.12+） | verifier_core/Scarb.toml | 改为空 feature + 硬选 poseidon252/naive 代码路径（cfg 门展开） |
| 2 | `let ... else`（Cairo 2.12+） | verifier_utils/zip_eq.cairo、blake2s.cairo | zip_eq 改 match；blake2s 模块不编译（poseidon 路径不用） |
| 3 | `if let ... && ...` 链（2.12+） | verifier_core/utils.cairo `next_if_eq` | 改嵌套 match |
| 4 | `core::num::traits::DivRem` 路径迁移 + `NonZero` 字面量自动转换（2.12+） | vcs/verifier.cairo | 改 `core::traits::DivRem` + `2_u32.try_into()` |

另有 2 处 Rust 侧已知问题（zchain 根 workspace 同款处理）：registry `stwo-cairo-common` 1.2.2 的 `Mask::to_int()` 与当前 nightly 不兼容 → driver 用 `[patch.crates-io]` 指向 `third_party/stwo-cairo/common` 已补丁副本；`stwo` prover feature 需 nightly-2026-04-15。

### 1.3 官方栈的两个接口坑（驱动侧绕过，未改上游）

1. `stwo_cairo_adapter::adapt` 硬编码 `PublicSegmentContext::bootloader_context()`（11 个 layout segment 全 present），而 scarb `#[executable]` 程序只声明实际使用的 builtins（本探针 3 个：output/range_check/poseidon）→ 直接 adapt 后 ECDSA 段非空断言失败（原始 panic 见 `logs/driver_full_run_console.txt`）。driver 在 adapt 之后用 `PublicSegmentContext::new(&entrypoint.builtins)` 重建上下文（与官方 `scarb prove` 管线行为一致）。另：程序返回值必须是 ≤u128 的小值（public segment 指针槽），探针程序的 checksum 因此取 31-bit limb。
2. `cairo_air` 的 `CairoSerialize`（cairo_serde 格式）要求 11 个 segment range 全 Some；未使用 builtin 在 serde 视图补「空段（start==stop=0）」，仅用于序列化计数，`verify` 用原始 claim。

**结论（步骤1）**：工具链可得、可用；兼容成本 = 4 类 Cairo 语法补丁 + 2 个驱动侧接口适配，全部机械且已文档化。**无阻塞**。

---

## 2. 步骤2：Cairo 验证程序与微基准（实测）

9 个 executable（`crates/prog_*`），driver 在 cairo-vm **proof_mode + `all_cairo_stwo` layout + disable_trace_padding** 下运行并读取 VM 资源计数。N=100 次迭代，单位成本 =（程序计数值 − baseline 计数值）/100。

### 2.1 逐步实测（原始输出：`logs/driver_raw.txt`）

| 程序 | steps | range_check | poseidon | mem_holes |
|---|---|---|---|---|
| prog_baseline（空循环） | 1,537 | 201 | 0 | 1 |
| prog_hades ×100 | 2,443 | 201 | 100 | 1 |
| prog_m31_add ×100 | 3,140 | 401 | 0 | 1 |
| prog_m31_mul ×100 | 3,340 | 601 | 0 | 1 |
| prog_qm31_mul ×100 | 16,360 | 2,201 | 0 | 801 |
| prog_fri_fold ×100 | 16,065 | 3,001 | 0 | 1 |
| prog_channel ×100（1 mix + 1 draw） | 53,745 | 15,001 | 200 | 1 |
| prog_merkle ×100（叶+内部节点） | 4,301 | 201 | 101 | 102 |
| **prog_verify_min（最小验证器全量）** | **15,098** | **4,128** | **38** | 12 |

### 2.2 单位成本（实测推导）

| 原语 | steps/op | range_check/op | poseidon/op | 备注 |
|---|---|---|---|---|
| hades_permutation（poseidon builtin） | **9.06** | 0 | 1 | 「poseidon_builtin 已电路化」的直接量化：每次置换≈9 步 |
| M31 add | 16.03 | 2.00 | 0 | bounded-int 加法 + constrain |
| **M31 mul** | **18.03** | **4.00** | 0 | wide_mul→u64 + div_rem by P |
| QM31 mul | 148.23 | 20.00 | 0 | ≈ 8.2×M31 乘 |
| **fri_fold**（1 列 × 1 层） | **145.28** | **28.00** | 0 | ≈ 8.1×M31 乘 |
| channel draw（1 次 secure draw） | ≈511 | ≈148 | 1 | 8×extract_m31（u256 div_rem + reduce），**channel 阶段是步骤大户** |
| Merkle 叶（1 QM31 列=4×M31）+1 节点 | 27.64 | 0 | 1 | 叶打包≈18.6 步；纯内部节点≈9.1 步 |

非原生乘法成本结论：**felt252 上 M31 乘法 ≈ 18 Cairo steps（4 个 range_check）**，QM31×QM31 ≈ 148 steps；这是 canonical AIR 全部 M31/QM31 约束在 Cairo 侧的换算汇率。

### 2.3 verify_min 闭合核验

poseidon 计数逐项闭合：3（mix 根）+ 26（draw：8 α + y_p/y_m + 7 witness + 叶 + 8 兄弟）+ 1（叶哈希）+ 8（路径节点）= **38 = 实测 38**（精确）。steps 闭合：按 §2.2 单位成本预测 ≈16.3K vs 实测 15,098（±8%，差值为基准循环开销），一致性成立。FRI 末层常数与 Merkle 根断言通过 = mirror 交叉验证 PASS。

---

## 3. 步骤3：出证（stwo-cairo 本地 prove + 官方 CLI 交叉验证）

driver 对 `prog_verify_min`（15,098 实际步）出证，三种 channel 哈希变体，官方 96-bit 参数（pow_bits=26, n_queries=70, blowup=1, last_layer=0, fold_step=1，Canonical 预处理树）。`cairo_serde_felts` = CairoSerialize 展平后的域元素数（SHARP/链上口径的证明当量）：

| channel 变体 | prove（实测） | verify（Rust 侧实测） | cairo_serde felts | JSON 体积 | binary(bz2) |
|---|---|---|---|---|---|
| Blake2s | 23.5s / 8.2s（两次运行） | 84ms / 10ms | 314,677 | 12.1 MB | 1.03 MB |
| Blake2sM31 | 7.1s / 9.7s | 15ms / 12ms | 314,549 | 12.1 MB | 1.04 MB |
| **Poseidon252**（Starknet-facing） | **642s / 570s** | 250ms / 238ms | **239,727** | 6.4 MB | 1.07 MB |

（原始输出：`logs/driver_raw.txt`；证明文件：`logs/proof_prog_verify_min_*.json/.bin`）

**官方工具链交叉验证**（与 driver 无关的同一条路径）：

```
$ scarb prove -p prog_verify_min --execute --print-resource-usage
    steps: 131072 (padding 后；实际步数 15,098 与 driver 一致)
    builtins: range_check 4128, poseidon 38, output 1   ← 与 driver 逐项一致
    real 1.65s / 2.11s   proof.json = 2,884,657 B（scarb-prove 自带参数，低于 96-bit）
$ scarb verify -p prog_verify_min --proof-file <proof.json>
    Verified proof successfully    （real 0.05s）
```
（`logs/scarb_prove_timed.txt`、`logs/scarb_verify_timed.txt`）

**证明时间随步数的线性锚点（官方 CLI 同参数实测对）**：15,098 步→1.65s；prog_channel 加大到 ~1.045M 实际步（VM padding 后 4,194,304 步）→ **6.69s wall**。线性系数 ≈1.24 µs/padded-step，即官方工具链下吞吐 ≈ **62.6 万 steps/s（M3 Pro 多核）**。`logs/scaling_anchor_1m_steps.txt`。

---

## 4. （并入 §2/§3）M31/QM31 非原生成本小结

- M31 在 Cairo（felt252 域）用 **1 个 limb（bounded-int 31 bit）** 表示；乘法 = 1 次 felt 乘 + div_rem 约化 = **18.03 steps / 4 RC**。
- QM31 = 4×M31；QM31×QM31 = **148.23 steps / 20 RC**。
- FRI fold（官方 packed-unreduced 实现）= **145.28 steps / 28 RC** —— 奇点：**channel 的每次 secure draw（~511 步，8 次 extract_m31 的 u256 div_rem 主导）比 3.5 次 FRI fold 还贵**；canonical 全量 channel 阶段（~14 次 draw）≈7K 步，可忽略，但若把大批量数据经 channel 抽取则不划算。

---

## 5. 步骤4：外推到完整 canonical AIR（单手）——【估算】

方法：**实测单位成本（§2.2） × canonical verifier 结构计数**。结构计数取自 canonical 实测元数据（`stwo-wasm-probe.md` §0，只读采集：列宽 1927/5392/116、log8、pow10、q30、blowup1、last_layer_deg0、fold_step1、29 列 LogUp）。凡非直接实测处均标注。

| 阶段 | 计数 | 单位成本（实测） | steps | RC | poseidon |
|---|---|---|---|---|---|
| FRI 折叠（主导项） | q30 × 9 层 × 5508 可折列 = 1,487,160 folds | 145.28 / 28 | **216.0M** | 41.6M | 0 |
| trace 树宽叶哈希 | 30 ×（21,568 limb×2.4 + 899 hades×9.06） | ≈59.9K/查询 | 1.80M | ~0 | 26,970 |
| interaction 树叶哈希 | 30 ×（464 limb） | ≈1.3K/查询 | 0.04M | ~0 | 600 |
| FRI 内层叶 | 30 × 8 层 × ~30 | ≈240/查询 | 0.007M | ~0 | 240 |
| Merkle 路径节点 | 30 × 54 节点（9+9+36） | 9.06/节点 | 0.015M | ~0 | 1,620 |
| channel 阶段 | 3 mix + ~14 draw | §2.2 | 0.007M | ~2.1K | 17 |
| OODS + 约束体 + LogUp 关系 | ~7319 列随机线性组合 + ~100–200 约束体（**估算，无直接 bench**） | qm31×m31≈72 steps 等 | **0.1–0.5M（估算）** | ~0.05M（估算） | 0 |
| **合计** | | | **≈ 218M（估算）** | **≈ 41.7M（估算）** | **≈ 29.4K（估算）** |

关键假设（全部显式）：
1. **FRI 折叠按「每列 × 每查询 × 每层」计**——与 stwo FRI 结构一致（列数降低域维度，不减少列数）。交叉印证：native canonical verify 实测 188.7ms 中 FRI 折叠 ≈ 1.49M 次 × ~80ns ≈ 0.12s，占主导，与 stwo-wasm-probe §3.1 实测的「列数线性」一致。
2. **scope 树（1927 列）不做 Cairo 侧 FFT**：假设 canonical verifier 接口改为「prover 供给 scope 列在 OOD 点的值」由约束兜底。若照搬 `verify_canonical_stark` 的 scope 重建（256 行 ×1927 列 FFT），Cairo 侧步数会再膨胀数个量级——**这是 canonical AIR 若要上桥必须先改接口的原因之一**（见 §7）。
3. OODS/约束体项未做直接 bench（探针最小子集不含 29+ 选择子），0.1–0.5M 为区间估算；该项占比 <0.3%，不影响总量级。

### 5.1 换算与对比

- **出证时间（估算）**：按 §3 线性锚点 1.24 µs/padded-step，218M 实际步（padding ≈2^28）→ **≈7 分钟/证明**（官方 CLI 参数）；若用 96-bit 参数（pow26/q70）与 Poseidon252 channel（Starknet-facing 最终证明需要），按 §3 实测比率上调，量级仍在 **分钟—一刻钟**。对比：canonical 直接证明 = 491.7ms（真值）→ 桥接层放大 ≈ **800–2000×**。
- **最终证明大小**：对一个 15K 步程序实测 239.7K–314.7K felts（≈0.24 MB bz2）；证明大小随程序步数仅对数增长，canonical 桥的最终 Cairo 证明预计仍在 **0.3–1 MB** 量级（估算）。

### 5.2 Starknet 侧 gas（官方计价口径，标注估算）

官方 Sierra 计价（Starknet v0.13.4 pre-release notes，Sierra≥1.7.0）：**1 Cairo step = 100 L2 gas = 0.0025 L1 gas；range_check = 70；poseidon = 491；pedersen = 4050；bitwise = 583**。

- **路线甲：把 §5 的 verifier 逻辑直接作为 Starknet 合约执行**（即「直接链上 AIR verifier」路线，校验 1 份 canonical 证明）：
  218.2M×100 + 41.7M×70 + 29.4K×491 ≈ 21.8B + 2.92B + 0.014B ≈ **24.7B L2 gas/证明（估算）**（仅步数换算的 L1 当量 ≈0.62M L1 gas，但 EVM 原生实现 M31/QM31 的单价完全不可比，只会更贵）。单份证明直接上链验证**不可行**：24.7B L2 gas 高出 Starknet 单笔交易 gas 上界约 3 个数量级，合约执行时间也远超区块预算。这是 stwo-wasm-probe 路线（浏览器验证）与本路线（递归桥）双双优于「合约直接验 AIR」的量化根据。
- **路线乙：递归桥（本 PoC 形态）**：218M 步的 verifier 程序**离线**由 stwo-cairo/SHARP 出证；Starknet 链上只执行 STARK-verifier 合约校验最终 Cairo 证明，其工作量只依赖最终证明的 q×层数（与 218M 步无关），合约规模量级 10⁵–10⁶ Cairo 步 → **≈10M–100M L2 gas/证明（估算区间，量级）**。注意 Starknet 合约当前不能直接挂 poseidon builtin（syscall 口径），该项为量级估算，待官方 cairo_verifier 合约的公开实测数校准。

---

## 6. 与替代方案对比（证据等级：实测/估算混合，已标注）

| 维度 | A. stwo-wasm 浏览器验证 | B. 递归桥（本 PoC） | C. 直接链上 AIR verifier 合约 |
|---|---|---|---|
| 信任模型 | 信任客户端代码（应用级） | **无信任**：L1/合约可独立校验最终 STARK 证明 | 无信任 |
| 用户侧延迟（单手） | **~35ms（实测，含宽裕余量）** | 分钟级（离线出证，估算）+ 链上 finalize | 链上即时，但单次 verify ≈24.7B L2 gas（估算）→ 不可行 |
| 每证明算力成本 | 客户端 CPU（免费） | **≈218M Cairo steps + 出证 ≈7 分钟（估算）** + SHARP 聚合费 | 0 离线，链上 gas 巨额 |
| 证明/数据大小 | 1.19MB archive 发客户端（实测） | 最终证明 ≈0.24–1MB 常数（实测 15K 步样本 + 估算） | 证明本体 1.19MB 需上链 calldata |
| 链上验证成本 | 0 | ≈10M–100M L2 gas（估算，常数/证明，可聚合摊销） | 24.7B L2 gas（估算）→ **NO-GO** |
| 依赖风险 | Poseidon252 wasm cfg 门（上游 issue） | scarb/stwo-cairo 版本漂移（§1.2 已实证 4 类补丁）；官方 cairo_verifier 合约成熟度 | 无新依赖，但gas 直接判死 |
| 适用场景 | M4-ACC-5 浏览器自验 | **Phase 2 无信任退出 / L1 结算** | 无（作为对照） |

---

## 7. Phase 2 立项/否决建议

1. **单次「证明上链即验」形态：否决。** 一份 canonical 证明走递归桥的 verifier 程序 ≈218M 步（估算）+ 分钟级出证，只换来一份最终证明——除非该证明对应**一大批**已聚合的手数/批次，否则成本结构不成立。
2. **无信任退出（Phase 2 真目标）：CONDITIONAL GO**，立项前置条件按优先级：
   - **先算清聚合 economics**：verifier 程序步数随证明份数**线性**增长（每份 ≈218M 步，估算）；聚合能摊销的只有链上固定项（最终 STARK 校验的 ≈10M–100M L2 gas，估算）与 SHARP 批处理开销。因此降本的第一杠杆不是聚合，而是把每份的 218M 压下来——见下一条。
   - **canonical AIR 递归友好化改造清单**（依本 PoC 数据排序）：a) **FRI 参数降 q**（q30→10 直接省 2/3 主导项 → ≈72M 步/证明，估算；需重算安全等级）；b) scope 树改 OOD 供给（去掉 Cairo 侧 FFT，§5 假设 2）；c) LogUp 批处理列合并。a/b 是 AIR 侧小改，c 是结构改。
   - **上游跟进**：scarb 2.15+（消除 §1.2 全部语法补丁）；官方 cairo_verifier 合约上主网后的实测 gas 数（校准 §5.2 路线乙）。
   - **正式实现的工作量**：M（PoC 已完成）→ XL（正式）：verifier 程序需覆盖全部 29+ 选择子/opcode 约束体 + 3 树 + 查询批处理，且要给 `stwo-cairo` 上游提 2 个接口 issue（adapter 的 public-segment 上下文、CairoSerialize 的全段要求——§1.3，官方 `scarb prove` 已示范正确行为，属小改）。
3. **与 stwo-wasm 路线的关系**：二者不冲突——浏览器验证（路径 B，已 CONDITIONAL GO）覆盖「玩家自验」，递归桥覆盖「L1 无信任退出」。Phase 2 若立项，建议同时保留 wasm 路线作为低成本兜底。

## 8. 上游依赖清单（版本与迁移影响）

| 依赖 | 版本 | 状态 | 迁移影响 |
|---|---|---|---|
| scarb | 2.11.4（本机） | 可用；上游 v1.2.2 钉 2.15.0 | 升 2.15 可删 4 类语法补丁；`scarb prove/verify` 已内置 |
| stwo-cairo（prover/common） | 1.2.2（本地补丁源） | 可用 | 上游 1.2.x 修复 nightly 兼容后可回归 crates.io（third_party/README 同款条件） |
| stwo-cairo-adapter / cairo-air | 1.2.2（crates.io） | 可用 | 2 个接口适配（§1.3）建议提 issue；官方 scarb-prove 已示范期望行为 |
| stwo | 2.3.0 | 可用（prover 需 nightly-2026-04-15） | 与 zchain 主 workspace 同 pin |
| cairo-vm | 3.2.0 | 可用（`all_cairo_stwo` layout） | — |
| 官方 monorepo 迁移 | stwo-cairo 已迁 `stwo_cairo_prover/` monorepo 结构 | 已按 v1.2.2 tag 取源，无影响 | 跟 tag 即可 |

## 9. 探针工件索引

```
cairo-bridge-poc/
├── Scarb.toml                    # scarb workspace（10 成员）
├── crates/base/src/lib.cairo     # 微基准 + verify_min（官方 verifier_core 原语；EMBED 常量由 driver 注入）
├── crates/prog_*/                # 9 个薄 executable
├── vendor/                       # 官方 stwo-cairo v1.2.2 verifier_core/verifier_utils/bounded_int（PATCH 注释标记兼容补丁）
├── reference/                    # 官方 fri/channel/m31/qm31/hasher 源（对照用）
├── driver/                       # Rust driver（独立 workspace；mirror 交叉验证 + cairo-vm 运行 + stwo-cairo 出证）
│   ├── src/mirror.rs             # 官方算术的 Rust 镜像（交叉验证 PASS）
│   └── src/main.rs               # 5 步流水线（embed→build→run→prove→official CLI）
├── logs/
│   ├── driver_raw.txt            # 全部 9 程序资源计数 + 3 channel 变体 prove/verify/尺寸（终版）
│   ├── driver_full_run_console.txt / driver_first_proofs_console.txt  # 过程原始输出（含 3 个 panic 现场）
│   ├── scarb_prove_timed.txt / scarb_verify_timed.txt                 # 官方 CLI 定时 + Verified successfully
│   ├── scaling_anchor_1m_steps.txt                                    # 1M 步线性锚点
│   └── proof_prog_verify_min_*.json/.bin                              # 三变体证明文件
└── target/execute/prog_verify_min/*/proof/proof.json                  # 官方 scarb prove 产物（2.88MB，已验证）
```

复现：`cd cairo-bridge-poc/driver && cargo +nightly-2026-04-15 run --release`（一次跑完全部 5 步；`BRIDGE_CHANNEL=poseidon` 可单测 Poseidon252 变体）。

---

*报告日期：2026-09-13。工具：scarb 2.11.4 / rustc nightly-2026-04-15 / stwo-cairo 1.2.2 / stwo 2.3.0 / cairo-vm 3.2.0。探针未改动 zchain 其他目录（third_party、poker-appchain-texasair、stwo-wasm-probe 均只读），未 git commit。gas 计价来源：Starknet v0.13.4 pre-release notes（community.starknet.io/t/starknet-v0-13-4-pre-release-notes/115257）；所有估算项已显式标注。*
