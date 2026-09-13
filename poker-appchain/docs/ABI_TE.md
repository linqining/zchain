# ABI_TE — TE-E0 收费枚举三仓对照（草拟，待主控合并进 ABI.md）

> 状态：**TE-E0 枚举先行**（判别值冻结）。本文档为新增枚举的对照与语义
> 边界说明；`ABI.md` 的正式收录由主控合并（A 任务在飞，ABI.md 冻结中），
> 合并时以本文为准迁移。

## 1. 判别值三仓对照表（冻结，不得重排或复用）

| 语义 | poker-settlement-core（u8 常量） | poker-appchain（`FeePolicy` borsh 判别值） | poker_texas_air（`canonical_rake_opening` `rake_mode`） |
| --- | --- | --- | --- |
| 零费 | `RAKE_MODE_NONE = 0` | `Zero`（变体序 0）/ `rake_mode::NONE = 0` | `0`（`CanonicalRakeOpening::ZERO`） |
| 固定比例（分账） | `RAKE_MODE_PERCENTAGE = 1` | `FixedRake{rate_bps, cap, split}`（变体序 1）/ `rake_mode::PERCENTAGE = 1` | `1`（`CanonicalRakeOpening::PERCENTAGE_MODE`） |
| 固定比例计费 + GAME 销毁处置 | `RAKE_MODE_FIXED_RAKE_BURN = 2` | `FixedRakeBurn{rate_bps, cap, split}`（变体序 2，末位追加）/ `rake_mode::FIXED_RAKE_BURN = 2` | `2`（`CanonicalRakeOpening::FIXED_RAKE_BURN_MODE`） |

对应源码锚点：

- settlement-core：`poker-settlement-core/src/lib.rs`（根导出常量）、
  `poker-settlement-core/src/derive.rs`（`compute_rake` 对 mode 2 fail-closed）。
- poker-appchain：`poker-appchain/src/fee.rs`（`FeePolicy` / `rake_mode` 模块）。
- poker_texas_air：`src/canonical_rake_opening.rs`（opening 常量与校验）、
  `src/texas_canonical.rs`（raked award 关系）、
  `src/texas_canonical_air.rs`（transcript mix / `RAKE_SCOPE_OFFSET` / AIR mode 根集）。

## 2. 语义边界：枚举先行、规则留合约

- **本任务（TE-E0）只落地判别值与最小映射**。GAME 桌销毁计费的**结算
  规则（销毁的资金处置：燃烧路径、事件、守恒闭合）在 poker_l1 合约侧
  实现，由 TE-M4 排期**；合约侧落地前，任何一层都不得把 mode 2 静默按
  mode 1 的资金处置语义结算。
- **计费数学不变**：mode 2 与 mode 1 的计费数量关系完全同式
  `min(floor(base * rate_bps / 10_000), cap)`（appchain `rake_of` /
  上游 `canonical_settlement_rake` / AIR 的 raked 算术恒等式）。burn 只是
  资金处置语义的差异，fee/opening/AIR 层只承载计价。
- **各层对 mode 2 的当前行为**：
  - poker-appchain `FeePolicy::FixedRakeBurn`：可构造、可绑定注册表、
    `rake_of`/`split_of`/`commitment` 与 `FixedRake` 同式（mode 进承诺 ⇒
    commitment 必然不同）；borsh 末位追加，既有判别值 0/1 数据兼容。
    结算/分账路径（`settlement.rs` / `note_v2.rs` 的 `FixedRake` 分支）
    暂不匹配该变体——现有流程不构造 burn 策略，行为不变；burn 分账到
    销毁的映射待 TE-M4 合约规则定稿后接线。
  - poker_texas_air：opening 校验接受 `0 | 1 | 2`；raked award 关系与 AIR
    的 mode 根集为 `{1, 2}`（fail-closed，其它值拒绝，mode 0 必须走
    plain award selector）。opening/AIR 只证计费数量关系。
  - poker-settlement-core：`derive_settlement_plan` 对 mode 2 显式
    fail-closed（Err，"settles in poker_l1"）——本 crate 只结算 0/1，
    不承担销毁结算语义。
- **结构形状说明**：`docs/plan-token-economy-v1.md` §3.5 以
  `FixedRakeBurn{rate_bps, cap}` 简写；TE-E0 落地形状为
  `FixedRakeBurn{rate_bps, cap, split: FeeSplit}`（与 `FixedRake` 同形，
  additive 纪律下计费/拆分数学复用；split 字段在合约侧销毁规则定稿前
  不产生链上资金流出语义）。
- ABI 编码：`SettlementRecord` 仍只携带 `policy_commitment`（32B
  poseidon，mode 为第二个 preimage 字段）；rake_audit export JSON 的
  `policy.mode` 透出 `2`。

## 3. 与 TE-v1 文档的引用关系

- 设计来源：`docs/plan-token-economy-v1.md`（GAME 桌 rake 即销毁，
  §3.5；里程碑 TE-M4）、`docs/plan-token-economy-compliance-v1.md`。
- 本文档是 ABI 面的**枚举对照附录**：判别值冻结声明、三仓一致性、
  语义边界。TE-M4 合约规则落地后，销毁处置的 ABI 语义（事件/守恒）
  在 ABI.md 正式版本补全。
- 判别值一致性由三仓测试钉死：
  - `poker-settlement-core`：`derive::tests::rake_mode_discriminators_are_frozen`
  - `poker-appchain`：`fee::tests::borsh_discriminants_are_frozen`
  - `poker_texas_air`：`canonical_rake_opening::tests::rake_mode_discriminators_are_frozen`
