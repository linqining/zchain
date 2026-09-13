# wallet-app — ZChain 独立桌面钱包 MVP（plan §6.12.5）

Tauri v2 桌面壳 + 复用 [`poker-wallet`](../poker-wallet)（wallet-core，plan §6.12.3）。
独立 Cargo workspace（自带 `Cargo.lock`），**不加入 zchain 根 workspace**，避免
feature/lockfile 污染（隔离模式参照 `poker-appchain-texasair`）。

## 路线选择记录（诚实降级点）

- **路线 A（Tauri v2）已落地**：本机满足 Tauri 系统依赖（macOS 15.3 arm64 +
  Xcode CLT `/Library/Developer/CommandLineTools` + 系统 WebKit），`src-tauri`
  的 `cargo check` 与 `cargo build --release --features custom-protocol`
  均通过（证据见"验收证据"）。
- 未触发降级路线 B（本地 HTTP server + 静态页）。UI 层仍保留了传输适配层
  （`ui/app.js`：有 `window.__TAURI__` 走 IPC，否则回落 `POST /api/<cmd>`），
  若未来需要无壳部署可直接复用同一套页面。
- **vendor 快照（诚实记录的外部干扰对策）**：并行 agent 正在根 workspace 持续
  重构 `poker-appchain`（note_v2 / aggregate / archive_index 等），构建窗口内
  两次撞上其中间编译态（`E0277`/`E0432`）。为不越界改他人文件、也保证本
  workspace 验收可复现，`vendor/` 内放置了 `git archive HEAD` 导出的
  `poker-wallet`/`poker-appchain`/`poker-settlement-core` 快照（**代码与上游
  仓库 HEAD 同源同字节**，仅将 manifest 的 `workspace = true` 继承依赖改写为
  与根 workspace 完全一致的具象版本）。`crates/zwallet` 的 path 依赖指向该
  快照。上游稳定后，删除 `vendor/`、把依赖路径改回 `../../../poker-wallet`
  与 `../../../poker-appchain` 即可（接口为钱包核心稳定面，无本目录私有改动）。

## 架构

```text
wallet-app/
├── Cargo.toml            # 独立 workspace（members: crates/zwallet, src-tauri）
├── Cargo.lock            # 独立 lockfile
├── ui/                   # 前端：纯本地静态资源（index.html / app.css / app.js），
│                         #   无框架、无 CDN、无互联网运行时代码
├── crates/zwallet/       # wallet-core 接线层（路线无关的業務核心）
│   └── src/{lib,persist,dto}.rs + tests/integration.rs
├── src-tauri/            # Tauri v2 壳（IPC 命令 1:1 暴露 zwallet + 原生对话框）
│   ├── src/{main,commands}.rs
│   ├── tauri.conf.json   # frontendDist = ../ui（编译期内嵌）
│   └── icons/            # 标准库生成的 RGBA PNG（无外部资源）
└── vendor/               # wallet-core HEAD 快照（见"路线选择记录"）：
                          #   poker-wallet / poker-appchain / poker-settlement-core
```

分层纪律（plan §6.12.3：壳层不得重实现协议逻辑）：

| 层 | 职责 | 不做什么 |
| --- | --- | --- |
| `wallet-core`（poker-wallet） | 密钥/keystore/note 分库/结构化签名/备份/展示门，**唯一密码学实现** | — |
| `zwallet` | 状态机（未初始化/锁定/解锁 + 自动锁屏）、数据目录持久化、DTO | 不实现任何密码学 |
| `src-tauri` | IPC 命令透传、原生文件对话框、数据目录落位 | 不绕过任何 wallet-core 检查 |
| `ui/` | 页面渲染（消费后端 DTO） | 不自行决定展示门（消费 `display` 输出） |

数据目录（默认 `~/Library/Application Support/dev.zchain.wallet-mvp`）与
poker-wallet CLI **同格式**（`keystore.json`/`dek.json`/`notes_real.json`/
`notes_play.json`/`sessions.json`/`checkpoint.json`/`nonces.json`，HexBlob JSON
内嵌 borsh）——CLI 与桌面钱包可互读对方数据目录（有集成测试锁定该格式）。

## 运行

```bash
cd wallet-app

# 1) 测试（wallet-core 接线层，19 项集成测试）
cargo test -p zwallet

# 2) 编译桌面应用（release，内嵌 ui/ 静态资源）
cargo build --release -p wallet-app --features custom-protocol
# 产物：target/release/wallet-app（macOS 可执行；`tauri build` 打包 .app 需 tauri-cli）

# 3) 运行
./target/release/wallet-app

# 开发期（若安装了 tauri-cli）
# cargo install tauri-cli --version '^2' && cargo tauri dev
```

## MVP 功能 ↔ wallet-core 接线点

| MVP 功能（§6.12.5） | 接线点（wallet-core API） | 壳层入口 |
| --- | --- | --- |
| 创建 ZChain Account | `key_manager::OwnerKeyPair::generate` + `keystore::seal_owner_key`/`seal_dek`（Argon2id + ChaCha20-Poly1305） | `create_wallet` |
| 导入 owner 私钥 | `OwnerKeyPair::from_secret_bytes`（32B 规范校验，fail-closed） | `create_wallet(secret_hex)` |
| 网络与 chain id 展示 | 固定 `zchain-devnet-1` / domain `zchain` / ABI v1（`operation_signer::SUPPORTED_ABI_VERSION`） | `status` |
| 应用锁（密码解锁） | `keystore::open_owner_key` / `open_dek`（口令错 → `BadPassword` fail-closed） | `unlock` / `lock_wallet` |
| 自动锁屏计时 | 壳层状态机：空闲超时即丢弃 secret（zeroize on drop），先锁后报错 | `set_auto_lock` + `status.lock_remaining_secs` |
| PLAY note 列表/余额 | `note_store::WalletStores`（REAL/PLAY 物理分库）+ `display::play_page_view` | `play_notes` / `demo_faucet` |
| 本地演示 faucet | 本地 `Note::new`（Play）+ `NoteStore::insert`；**明示"本地演示数据"，不伪造链上余额** | `demo_faucet` |
| 逐字段签名确认页 | `operation_signer::Signer::preview`（`SigningPreview` 逐字段直显）→ `Signer::sign` | `preview_sign` / `confirm_sign` |
| 拒绝非结构化字节签名 | `Signer::sign_raw_bytes` 恒 `RawBytesRejected`（UI 负例按钮可验证） | `sign_raw_bytes` |
| 加密备份导出/导入 | `backup::export_backup` / `import_backup`（口令→DEK→双库→索引自检全链路，fail-closed） | `backup_export` / `backup_import` |
| REAL 展示门（无提现入口） | `display::real_page_view(&ReadinessFlags::offline(), …)`：claim/提现隐藏 + 托管提示 | `status.balances.real_view` |

签名确认页逐字段展示 `SigningPreview` 的全部字段：网络（chain id/domain/ABI）、
资产类、输入/输出总额、rake、桌 ID、输出 owner、request_id、hand_binding、
各输入 proof 状态、过期时间、nonce、确认摘要——**展示与签名摘要绑定同一数据**
（M6-ACC-7 / WALLET-ACC-2）。

## 验收证据

```bash
# 1) wallet-core 接线层测试（19/19 绿；覆盖签名/备份恢复/fail-closed/自动锁/CLI 格式互通）
cargo test -p zwallet
#   account::create_then_status_shows_network_and_owner
#   account::import_owner_secret_is_deterministic
#   account::create_rejects_short_password_and_double_init
#   account::wrong_password_unlock_fails_closed
#   notes::demo_faucet_then_balances_and_notes
#   notes::real_display_gate_offline_has_no_claim_entry
#   notes::locked_wallet_rejects_note_views
#   signing::transfer_preview_then_sign_field_by_field
#   signing::buy_in_preview_carries_table
#   signing::expired_request_rejected
#   signing::real_asset_rejected_at_app_boundary
#   signing::raw_bytes_signing_is_always_rejected
#   backup::export_import_roundtrip_restores_notes
#   backup::wrong_password_import_fails_closed_and_does_not_touch_dir
#   backup::tampered_backup_rejected
#   backup::future_version_backup_rejected_before_decryption
#   app_lock::auto_lock_fires_after_timeout_and_relock_works
#   app_lock::settings_persist_across_reopen
#   cli_interop::data_dir_files_match_poker_wallet_cli_layout

# 2) 桌面壳编译
cargo check -p wallet-app
cargo build --release -p wallet-app --features custom-protocol
# 产物：target/release/wallet-app（12,158,800 字节，优化构建，内嵌 ui/ 资源）
```

### 实测记录（2026-09-12，本机真实执行输出摘录）

```text
$ cargo test -p zwallet
running 19 tests ... test result: ok. 19 passed; 0 failed

$ cargo check -p wallet-app
Finished `dev` profile [unoptimized + debuginfo] target(s)

$ cargo build --release -p wallet-app --features custom-protocol
Finished `release` profile [optimized] target(s) in 1m 08s
target/release/wallet-app  (12,158,800 字节)
```

**CLI 互通（上游 poker-wallet CLI 直接读写 zwallet 创建的数据目录）**：

```text
$ cargo run -p zwallet --example cli_interop -- /tmp/zwallet-interop
$ target/debug/poker-wallet --dir /tmp/zwallet-interop unlock --password demo-pass-123
ok: owner=02a4537da9af08fa46bdc06d471472d223ac10ebae159a647372e23ac046d8cca8
PLAY: free=200 locked=0          # zwallet 侧 demo_faucet(120)+demo_faucet(80)

$ poker-wallet --dir /tmp/zwallet-interop unlock --password wrong-pass
error: keystore authentication failed (wrong passphrase or corrupted envelope)   # fail-closed

$ poker-wallet --dir /tmp/zwallet-interop notes --password demo-pass-123
  01b72bf5… amount=80  proof=soft nullifier=0386bfec…
  07b1ba0e… amount=120 proof=soft nullifier=04d09f3b…

$ poker-wallet --dir /tmp/zwallet-interop faucet-play --amount 120 --password demo-pass-123
faucet ok: +120 PLAY             # CLI 侧写入 → PLAY: free=320（双向互通）

$ poker-wallet --dir /tmp/zwallet-interop sign --file req.json --yes --password …
== ZChain signing request ==
  kind: transfer   network: zchain-devnet-1 (domain zchain)   abi_version: 1
  asset_class: PLAY   amount_in: 80   amount_out: 80   rake: 0
  output: 80 -> 02a4537d…   proof[0]: soft   nonce: 0
  digest: 126f04842ff65423fb9d03d1f84d8f0bed260f32f88684ac4fe397dc5a3b6c2d
  operation_borsh: 040100000001b72bf5…（完整账本操作）

# 同一请求重放 →
error: nonce replay detected: chain=zchain-devnet-1 nonce=0
```

**GUI 手动清单的执行边界（如实标注）**：窗口渲染/点击流未在本次交付中人工
执行（agent 环境无 GUI 交互验收手段）；所有业务行为均有 `cargo test` 或上述
CLI/示例执行痕迹。UI 前端仅做本地静态校验（`node --check app.js` 通过、HTML
标签配平检查通过），跑通窗口交互需要在桌面环境执行
`./target/release/wallet-app`。

## MVP 边界（§6.12.5 清单中未做项，如实列出）

- **faucet / 链上连接**：无网络 IO。PLAY note 为本地演示铸造（UI 明示）；
  `sync::ChainSource`/`vault_adapter` 仍是无网络的内存接入缝。
- **REAL 提现 / claim**：未上线；离线展示门隐藏全部入口（§6.9 纪律）。
- **生物识别 / 系统 Keychain**：未接；应用锁 = 口令解锁本地 keystore 信封。
- **多设备同步**：无；加密备份文件是唯一恢复途径。
- **签名暴露面**：仅 `transfer` / `buy_in`；`settle` / `withdraw` /
  `key_rotation` 的核心能力在 wallet-core 已存在，但 UI/DTO 未暴露（属后续
  里程碑：settle 需要运算符侧结算记录骨架的分发通道）。
- **会话密钥（delegated key）管理页**：核心能力在 wallet-core，壳层 MVP 未做。
- **`tauri build` 打包 .dmg/.app**：未执行（需要 tauri-cli/bundler）；以
  `cargo build --release --features custom-protocol` 的可执行产物为验收。

## 安全纪律执行

- 前端资源 100% 本地（`ui/` 三文件 + 标准库生成的图标），无互联网运行时。
- CSP：`default-src 'self'`（tauri.conf.json）。
- 口令/私钥不进日志：命令层不做任何 secret 的 Debug/Display；wallet-core
  `SecretBytes` 的 `Debug` 恒输出 `[REDACTED]`。
- 任意字节签名：不存在该能力（恒拒绝），UI 提供负例按钮验证。
- 备份导入 fail-closed：坏口令/篡改/未来版本/索引不一致一律拒绝，且在全部
  校验通过前不写目标数据目录。
- 不 git commit（本目录新增文件保持工作区未提交状态）。

## 实测记录

见"验收证据 → 实测记录"。所有命令均在 2026-09-12 于本机执行，输出为真实摘录。
