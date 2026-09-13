# stwo-wasm-patch — vendored stwo 2.3.0（path A 补丁副本）

## 来源与保真

- 上游：crates.io `stwo` 2.3.0（registry 源码目录
  `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/stwo-2.3.0`），
  逐文件复制为 `stwo-2.3.0/`。
- 与 registry 副本的完整差异存档：`PATCH-vs-crates-io-2.3.0.diff`
  （`diff -ru` 全树输出）。
- **唯一实质（功能）变更**：poseidon252 家族的排除门
  `#[cfg(not(target_arch = "wasm32"))]` → `#[cfg(feature = "wasm-poseidon")]`，
  共 **16 个门 / 15 处替换 / 8 个文件**：

| 文件 | 门数 | 内容 |
|---|---|---|
| `src/core/channel/mod.rs` | 2 | `mod poseidon252` + `pub use Poseidon252Channel` |
| `src/core/vcs/mod.rs` | 1 | `pub mod poseidon252_merkle`（Poseidon252MerkleHasher） |
| `src/core/vcs_lifted/mod.rs` | 1 | `pub mod poseidon252_merkle`（Poseidon252MerkleChannel） |
| `src/core/vcs_lifted/verifier.rs` | 1 | poseidon merkle 测试（一致性起见同门） |
| `src/prover/backend/simd/mod.rs` | 4 | use + `poseidon252`/`poseidon252_lifted` 模块 + `BackendForChannel<Poseidon252MerkleChannel> for SimdBackend` |
| `src/prover/backend/simd/poseidon252.rs` | 1 | `use core::vcs::MerkleHasher`（MerkleOps 实现内） |
| `src/prover/backend/cpu/mod.rs` | 3 | use + `poseidon252` 模块 + CpuBackend 同型 impl |
| `src/prover/backend/simd/grind.rs` | 3 | poseidon PoW grind 模块 + 2 个测试 |

- 非功能（元数据/文档）变更：
  - `Cargo.toml`：新增 `wasm-poseidon` feature（**default 开启**：`default = ["std", "wasm-poseidon"]`）；
    新增空 `[workspace]` 表（使 vendored crate 自成 workspace 根，与 zchain 根
    workspace 隔离——与 `stwo-wasm-probe` 同模式）；头部 provenance 注释。
  - 8 个被改源文件头部 provenance 注释。
  - 本 README 与 diff 存档。

## 为什么是 feature 门（default 开）而不是直接移除门

1. **保留上游本意的逃生口**：上游用 target 门把 wasm 构建里的 poseidon 排除
   （推测动机：省二进制体积 / 不需要 starknet-crypto 时少拉依赖）。feature 门
   保留了"无 poseidon 的 wasm verifier"这一构建形态，只是从"按目标硬排除"改为
   "显式可选项"。
2. **对存量消费者零行为变化**：native 上原本就编译 poseidon252，feature 门
   default 开启后 native 行为逐字节一致；wasm 侧默认与 native 一致（最少惊讶），
   canonical 证明（Poseidon252 承诺）在浏览器端开箱可验。
3. **对上游 issue 请求是最小形**：请求就是把隐式 target 门改为显式 feature 门，
   上游可自选 default 取向。

## 依赖前提（解除门不是"新能力"，是"去预防"）

poseidon252 家族在 wasm32 上的全部依赖是 `starknet-crypto 0.6.2`
（`poseidon_hash/poseidon_hash_many/poseidon_permute_comp`，纯 Rust）+
`starknet-ff 0.3.7`。stwo 2.3.0 本就无条件依赖二者（`default-features = false,
features = ["alloc"]`），且在 wasm32-unknown-unknown 上编译通过——实测证据见
`stwo-wasm-probe/`（`logs/wasm_check_default.txt` 等三个 feature 变体 EXIT=0，
依赖树含 wasm-bindgen/js-sys/getrandom 链全部编译）。原门是预防性的，不是
技术性的。

## 使用方式（仅在本补丁的消费者 workspace 内生效）

```toml
# stwo-wasm-verify/Cargo.toml（独立 workspace，不动 zchain 根 workspace）
[patch.crates-io]
stwo = { path = "../third_party/stwo-wasm-patch/stwo-2.3.0" }
```

`[patch.crates-io]` 把整张依赖图里 `stwo = "2.3"` 的来源重定向到本副本
（包括 poker_texas_air 的传递依赖），registry 原件不动。

## 上游 issue 草稿

见 `docs/stwo-wasm-path-a.md`（zchain 仓库）§Upstream issue draft（英文全文）。
