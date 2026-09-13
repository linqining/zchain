# poker-wallet（wallet-core + CLI 钱包）

ZChain 共享钱包核心（plan-appchain §6.12.3 的 Rust 实现，lib 名 `wallet_core`）
与一个最小可用 CLI 钱包应用（§6.12.5）。浏览器扩展、Web 钱包、桌面/移动应用
**不得**各自实现密码学与 Note 逻辑——全部复用本 crate。

依据：`docs/plan-appchain-v1.md` §6.12.1a（Stark curve/SNIP-12）、§6.12.2
（账户模型）、§6.12.3（共享钱包核心）、M6/WALLET-ACC 验收门槛。

## 模块地图

| 模块 | 职责 | 要点 |
|---|---|---|
| `key_manager` | secp256k1 owner key 生成/导入；delegated/session key 生成与约束执行 | secret 常驻 `SecretBytes`（zeroize on drop，Debug 脱敏）；`session_admission` 是 Appchain 可复用的纯函数（scope/单笔与日限额/桌白名单/时间窗/换网/撤销，fail-closed） |
| `keystore` | Argon2id + ChaCha20-Poly1305 加密信封 | OWASP interactive 基线（m=19MiB, t=2, p=1）；canary + AAD 域钉扎；口令错/篡改/未来版本 fail-closed |
| `note_store` | note + spend secret + nullifier + 创建帧 + proof 状态的加密存储 | **REAL/PLAY 物理分库**（两个独立 `NoteStore` 实例；插入类检查 + 快照 AAD 钉资产类——REAL 文件永远打不开为 PLAY）；按资产类聚合余额 |
| `operation_signer` | 只接受结构化 `SigningRequest` 的签名器 | 人类可读预览（网络/资产类/金额/桌/输出 owner/rake/request_id/hand_binding/proof 状态/过期）；`sign_raw_bytes` 恒拒绝（无 signBytes 默认能力）；摘要含 chain_id/domain/ABI；结算签名完备后过账本全量校验才放行 |
| `account_binding` | SNIP-12 `AuthorizeZChainKey` / `RevokeZChainKey` typed data + Poseidon 摘要 + Stark 签名验证 + binding 状态机（active/expired/revoked/exhausted） | revision 1（成员名字母序、sn_keccak 截断 250 bit、`H(prefix, domain_sep, struct_hash)`）；`binding_admission` 纯函数供 Appchain 复用 |
| `verifier` | 接入 poker-appchain 校验面 | `validate_settlement`（守恒+费率+分账+签名覆盖）、软确认帧 `verify_chain`、批次根 Poseidon 复算 + golden 向量复算；输出 verifier 版本 + digest + 状态层级（local/soft/proven/finalized） |
| `backup` | 全库加密导出/导入 | `ZCBK` 魔数 + 版本头（未来版本解密前拒绝）+ AEAD + 声明索引；恢复后重建 commitment/nullifier/spent 索引与声明索引自检；版本迁移点 `migrate_payload` |
| `sync` | checkpoint / owner 索引同步 | `ChainSource` trait + 内存实现（断点续传、幂等、重组检测 `ReorgDetected`）；真实网络留接入缝，如实标注 |
| `vault_adapter` | 外部 Starknet 钱包连接面 | `getCapabilities` 风格能力探测、deposit/claim 请求构造；**类型层不持外部私钥**；claim 必须 finalized |
| `display` | REAL/PLAY 展示门状态机（纯逻辑） | REAL 页 claim 仅在 vault+verifier+BFT 全就绪时显示，否则隐藏并给托管风险提示；`PlayPageView` 类型上没有 REAL 字段 |

CLI（`src/bin/poker-wallet.rs`，JSON 文件驱动、离线可用）：

```text
init [--secret-hex] [--chain]   unlock    balances    notes（REAL/PLAY 分栏）
faucet-play --amount            sign --file req.json [--yes] [--session BINDING]
backup --out FILE               restore --in FILE     verify --file proof.json
session new-key | authorize | revoke | list
```

数据目录：`keystore.json`（owner 信封）、`dek.json`（DEK 信封）、
`notes_real.json` / `notes_play.json`（物理分库快照）、`sessions.json`、
`session_<id>.json`（会话密钥，DEK 封装）、`checkpoint.json`、`nonces.json`。

## 安全不变量

1. **私钥/spend secret 不落明文**：只存在于 `SecretBytes`（`Zeroizing` 容器，
   drop 清零）；`Debug` 输出 `[REDACTED]`（有单测断言）；备份字节中扫描不到
   任何私钥/spend secret（M6-ACC-8 有断言）。
2. **fail-closed**：口令错、密文篡改、版本未来、域/ABI 未知、金额溢出、
   会话越权/过期/撤销/重放——全部显式拒绝，无"尽力恢复"路径。
3. **无盲签**：签名入口只接受封闭枚举 `SigningRequest`；`sign_raw_bytes`
   恒返 `RawBytesRejected`。
4. **REAL/PLAY 物理隔离**：分库实例 + 插入类检查 + 快照 AAD 钉类；
   `PlayPageView` 无 REAL 字段。
5. **展示=签名内容**：预览的每个字段进入确认摘要 `preview_digest`
   （含 chain_id/domain/ABI 版本，跨网络必不同）。
6. **不持外部私钥**：`vault_adapter` 无密钥字段；Starknet 账户只有
   address + 授权证明；本 crate 不做 Starknet 账户私钥管理。
7. **无网络 IO**：`sync::ChainSource` / `vault_adapter::VaultProvider` 是
   真实网络实现的接入缝，当前只有内存实现（如实标注，不假装在线）。

## 密码学复用纪律

- Poseidon / Stark 曲线验签：`starknet-crypto 0.6`（workspace 既有）
- secp256k1 ECDSA：`secp256k1 0.29`（workspace 既有；与 poker-appchain
  `spend_digest`/`effect_digest` 验证路径完全一致）
- 结算语义：`poker_appchain::settlement::validate_settlement` 直接调用，
  不重实现
- SNIP-12 rev1 需要 sn_keccak：`sha3`（Keccak256，workspace 既有）
- 新增依赖仅：`argon2`、`chacha20poly1305`、`zeroize`（均入 workspace.dependencies）
- 随机源：`rand`（workspace 既有，OsRng）

## M6 / WALLET-ACC 覆盖对照表

测试位置：`src/*/tests`（单元）+ `tests/acceptance.rs`（集成，20 个）。
全部通过：`cargo test -p poker-wallet --release`（43 个测试）。

| 验收条目 | 状态 | 覆盖测试 | 说明 |
|---|---|---|---|
| M6-ACC-1 浏览器验证吞吐 | 未覆盖 | — | 浏览器 WASM 长会话面，非本 crate |
| M6-ACC-2 离线恢复 | **覆盖** | `m6_acc_2_8_backup_roundtrip_restores_everything` | 备份导入后 note/承诺/nullifier/proof 状态完整 |
| M6-ACC-3 伪造拒绝 | **覆盖** | `m6_acc_3_verifier_accepts_valid_and_rejects_tampering`、`m6_acc_3_verifier_rejects_tampered_soft_frames_and_batch_root` | 篡改 payout/pot/hand_binding/软帧/batch root 全拒并给原因 |
| M6-ACC-4 恢复演练 | **覆盖** | `m6_acc_4_recovery_drill` | 生成→销毁实例→恢复→余额与 note 完整（测试即演练） |
| M6-ACC-5 钱包兼容性 | 部分 | `wallet_acc_3a_*`（verifier 交叉验证逻辑面） | 外部钱包真实连接/签名属集成面；SNIP-12 摘要+Stark 验签路径已验证 |
| M6-ACC-6 插件安全 | 部分 | nonce 重放/域校验逻辑面（`wallet_acc_3_*`） | origin 绑定、CSP、消息通道是浏览器扩展面，未覆盖 |
| M6-ACC-7 签名可读性 | **覆盖** | `m6_acc_7_preview_fields_complete`、`m6_acc_7_reject_unknown_domain`、`m6_acc_7_reject_unknown_abi_version`、`m6_acc_7_reject_amount_overflow_and_conservation` | 预览字段完整性 + 未知域/未知 ABI/溢出三类拒绝 |
| M6-ACC-8 备份恢复 | **覆盖** | `m6_acc_2_8_*`、`m6_acc_8_backup_never_exports_plaintext_keys` | commitment/spend secret/nullifier/spent 状态完整恢复；导出无明文私钥（字节扫描断言） |
| WALLET-ACC-1 外部钱包兼容矩阵 | 未覆盖 | — | 真机集成面 |
| WALLET-ACC-2 跨端一致性 | 部分 | `wallet_acc_2_digest_separation`、`wallet_acc_3a_*` | 摘要确定性与跨网络/ABI/域分离已覆盖；WASM/移动端签名字节一致性与 typed-data 逐字段比对是集成面 |
| WALLET-ACC-3 恶意 dapp | **覆盖（逻辑面）** | `wallet_acc_3_reject_raw_bytes_replay_and_expiry`、`wallet_acc_3_session_scope_limit_expiry_revocation` | 任意 bytes 拒、nonce 重放拒、过期/未生效/撤销/超单笔/超日限/换网/KeyRotation 越权全拒；伪造 origin 是浏览器面未覆盖 |
| WALLET-ACC-3a 会话密钥授权 | **覆盖** | `wallet_acc_3a_authorize_digest_verifiable_by_stark_crypto`、`wallet_acc_3a_admission_all_reject_reasons` | AuthorizeZChainKey 摘要经 starknet-crypto 验签（正例+换钥/换摘要/换签名负例）；admission 每类拒绝独立断言 |
| WALLET-ACC-4 敏感数据不落日志 | 部分 | `keystore::tests::debug_never_leaks_secret`、`m6_acc_8_*` | 类型层 Debug 脱敏 + 备份字节扫描；crash dump/遥测/剪贴板扫描是发布工程面 |
| WALLET-ACC-5 备份 fail-closed | **覆盖** | `wallet_acc_5_backup_fail_closed`、`keystore_*` 单元 | 错误口令/篡改/未来版本/魔数全拒；恢复索引一致 |
| WALLET-ACC-6 REAL/PLAY 展示门 | **覆盖（逻辑面）** | `wallet_acc_6_real_claim_gating_and_play_isolation` | claim 门状态机 + 托管提示 + PLAY 页无 REAL 字段 + 未 finalized 不可 claim；实际 UI 渲染未覆盖 |
| WALLET-ACC-7 能力显示 | 部分 | `vault_capabilities_probe`、单测 | getCapabilities 逻辑面覆盖；硬件/Passkey 真机未覆盖 |
| WALLET-ACC-8 发布工程 | 未覆盖 | — | 可复现构建/SBOM/审查报告属发布流程 |

REAL/PLAY 物理分库：`physical_split_cross_store_invisibility` + note_store 单元
（跨库不可见、跨类插入拒绝、快照换类打不开）。
sync 断点续传/幂等/重组：`sync_resume_with_checkpoint_and_idempotence` +
sync 单元（重组检测）。

## 已知边界（如实标注）

- SNIP-12 摘要实现覆盖本 crate 用到的类型子集（shortstring/felt252/amount/
  bytes/T[]）；`bytes` 用标准 31B 大端分块。与 Argent X/Braavos 的
  真机互操作（`starknet_signTypedData`）未验证。
- Stark 签名本地验证等价于单签账户验证路径；多签/Passkey 合约账户的授权
  以链上 account contract 登记为准（本 crate 不冒充链上验证）。
- session key 的日限额窗口由调用方携带的 `daily_used` 聚合决定（CLI 在
  签名后记账）；跨设备日限聚合需要服务端登记（AccountBindingRegistry），
  属后续项。
- CLI 的 settle 请求以 borsh hex 携带 `SettlementRecord`/`FeePolicy`
  （`record_borsh`/`policy_borsh` 字段）；表单化 settle JSON 是 UI 层后续项。
- 真实网络同步与外部钱包连接只有 trait 接入缝 + 内存实现，无任何网络代码。

## 运行

```bash
cargo test -p poker-wallet --release   # 43 个测试（23 单元 + 20 集成）
cargo build --workspace --release      # 不破坏 workspace
```
