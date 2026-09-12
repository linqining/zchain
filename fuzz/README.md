# fuzz/ — poker-appchain 结构化 fuzz 目标（B4 / M8-ACC-7）

cargo-fuzz 传统布局（`fuzz/Cargo.toml` + `fuzz_targets/`）。三个 target 全部
走 `poker_appchain` 的**公开 API**，`arbitrary` 派生结构化输入，同时保留
原始字节路径（borsh 解码）。约定：**任何 panic 即失败**——全部拒绝路径必须
以 `Err` 返回（fail-closed 语义的运行时验证）。

## 如何运行

```bash
# 安装（需要 nightly 工具链）
cargo install cargo-fuzz

# 每个 target 跑 60 秒（在 fuzz/ 目录内执行；cargo-fuzz 0.13 起 run 不再接 -p）
cargo fuzz run note_abi           -- -max_total_time=60
cargo fuzz run soft_confirm_api   -- -max_total_time=60
cargo fuzz run settlement_witness -- -max_total_time=60
```

说明：

- `--sanitizer none` 可在 asan 环境异常时降级使用（结构 fuzzing 目标
  不依赖内存消毒器发现 panic；asan 能额外捕获 OOB/UAF）。
- 失败输入会落在 `fuzz/artifacts/<target>/`（crash-*.clone 文件）；
  回归：`cargo fuzz run <target> <crash-file>`。
- fuzz/ 是独立 workspace（`[workspace] members = ["."]`），不并入主
  workspace；libfuzzer/nightly 依赖与主 workspace 的 stable 构建隔离。

## 三个 target 覆盖的拒绝路径

### `soft_confirm_api`
- 原始字节：`SoftConfirmFrame`/`SignedFrame`/`Vec<SignedFrame>`/`Operation`
  （含 `Settle` 嵌套 record）的 borsh 解码——截断/坏判别 → `Err`；
  `verify_chain` / `verify_against`（坏签名/断链/坏 index）→ `Err`；
  `frame_hash` / `effect_digest` 对任意解码成功载荷可计算。
- 结构化：任意形状操作 → `Sequencer::submit` 软确认提交 API 全部在线
  拒绝路径（限流、幂等键、桌准入、签名校验、守恒、nullifier 查重、
  空买入）→ `Err`；成功/失败后链导出、头哈希、状态根不 panic。

### `note_abi`
- 原始字节：`Note`/`NoteSpec` borsh 解码（截断/坏 AssetClass 判别/越界
  数组 → `Err`）；解码成功后承诺/nullifier 计算（含非法压缩公钥——
  上层签名验证拒绝，哈希侧安全）。
- 结构化：`AssetClass::from_u8` 非法值拒绝；`Note::new` 零面额
  `InvalidAmount`；`NoteSpec::mint` 承诺与直接构造逐位一致；borsh
  往返承诺不变（ABI 稳定不变量）。

### `settlement_witness`
- 原始字节：`SettlementRecord`（嵌套 SettleInput/NoteSpec/plan/
  hand_proof）borsh 解码 → `Err`；解码成功后 `validate_settlement`
  （配默认 `FeePolicy::Zero`）全清单拒绝路径：零 hand_binding、空
  inputs、plan 版本/边界/守恒/runout 投影、pot != plan.gross_pot、
  承诺不匹配、零 nullifier、垃圾 ECDSA、费率不匹配、守恒破裂、分账
  缺失 → `Err`；`settlement_binding`/`payout_root`/`settle_effect`
  摘要对任意解码成功载荷可计算且确定。
- 结构化：形似合法的双输入 witness（垃圾签名/任意金额）走遍上述校验。

## 运行证据（2026-09-12，B4 关闭时）

见 `poker-appchain/docs/BLOCKERS.md` B4 条目：三个 target 各
`-max_total_time=60`，0 panic / 0 crash。
