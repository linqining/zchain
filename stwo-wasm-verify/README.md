# stwo-wasm-verify — path A：canonical 真证明的浏览器端 STARK 验证器

独立 cargo workspace（自带 lockfile，不进 zchain 根 workspace；与
`stwo-wasm-probe` 同一隔离模式）。保持 canonical 证明格式不变，把
poker_texas_air 的 canonical 验证器原样编译进 wasm32，实测延迟并接入
extension proof portal。实施报告：`docs/stwo-wasm-path-a.md`。

## 布局

```
Cargo.toml                # 虚拟 workspace + [patch.crates-io]（stwo → vendored 副本）
.cargo/config.toml        # wasm32 下 secp256k1-sys 用 brew llvm clang 编译（见下）
proofs/                   # gen-canonical 产出的真实 canonical 证明（borsh 归档）
crates/verify-core/       # crate A：verify_canonical_proof_wasm(archive_bytes) -> Result<VerifyStats>
crates/wasm/              # crate B：cdylib，手写 C ABI（sv_alloc/sv_free/sv_verify/sv_stats/...）
crates/gen-native/        # 原生出证工具（poker_texas_air prove 路径，3 桌各一份真证明）
wasm/stwo_verify_loader.mjs  # 宿主侧胶水（node/浏览器共用；fail-closed 导入桩）
harness/bench.mjs         # 延迟基准（≥10 次/证明，p50/p95 对照 500ms 门槛 + 篡改负例）
logs/                     # 原始输出（bench_run_*.txt / wasm_bench_result.json）
target-wasm/              # wasm32 构建产物（CARGO_TARGET_DIR 隔离）
```

## 关键机制

- **stwo 补丁只在本 workspace 生效**：`[patch.crates-io] stwo = { path =
  "../third_party/stwo-wasm-patch/stwo-2.3.0" }` 把整张依赖图（含 poker_texas_air
  的传递依赖）的 `stwo = "2.3"` 重定向到 vendored 副本（poseidon252 家族从
  wasm32 cfg 门改为 default 开启的 `wasm-poseidon` feature 门）。registry 原件、
  zchain 根 workspace、poker_texas_air 均零改动。
- **poker_texas_air 只读 path 依赖**：验证逻辑即
  `verify_canonical_tagged_proof`，未做任何改写。曾评估 `#[path]` 模块链降级
  方案（模块闭包 33 文件且 canonical_rake_opening 仍需 poker_l1），未采用；
  全量 path 依赖在 wasm32 直接编译通过的堵点是 poker_l1 的 secp256k1-sys
  （C 代码），用 brew llvm 的 clang（带 wasm32 后端）编译其官方
  wasm/wasm.c 解决（`.cargo/config.toml`，仅本 workspace）。
- **诚实计时**：wasm32 无时钟 syscall（`Instant` 会 panic），wasm 内不做计时，
  墙钟一律宿主侧测；`VerifyStats.internal_elapsed_ms` 仅 native 有值。
- **fail-closed 导入桩**：getrandom 的 js feature（feature 统一）拖入 5 个
  wasm-bindgen 占位导入；loader 满足链接但调用即抛错（验证路径是确定性的，
  触发即说明跑偏）。

## 常用命令

```sh
cargo test -p stwo-verify-core                                   # native 单测
cargo run --release -p gen-canonical                             # 生成 3 份真实证明
CARGO_TARGET_DIR=target-wasm RUSTFLAGS="-C target-feature=+simd128" \
  cargo build --release --target wasm32-unknown-unknown -p stwo-verify-wasm
node harness/bench.mjs target-wasm/wasm32-unknown-unknown/release/stwo_verify_wasm.wasm
```

实测（Apple M3 Pro，node v24.4.1）：native verify p50 195–201ms（对照 texasair
perf_baseline 188.7ms ✓）；wasm verify p50 1735ms / p95 1861ms（simd128 构建，
plain 构建 p50 1796 / p95 1982）——**超 500ms 门槛约 3.5×，按 path A 决策口径
（性能不敏感）如实交付，优化留后续**。9/9 篡改/截断负例全部拒绝。
