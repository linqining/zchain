# ABI TE-M4：GAME 桌 FixedRakeBurn 结算规则（排期表 §6 TE-M4）

状态：**已实现**（poker-settlement-core / poker_l1 texas_poker / poker-appchain）。
设计依据 `docs/plan-token-economy-v1.md`（TE-v1 语义：GAME 币计价 rake、
结算时直接销毁、供给紧缩）与排期表 §6 TE-M4 行（出口 = 合约侧销毁结算
规则 + e2e GAME 桌一手）。前置：TE-E0（判别值 2 冻结、计价同式）、
TE-M1/2/3（AssetId / v2 账本 / GTS 注册表与 Issue/Burn、
`game_outstanding = Σminted − Σburned`）。

纪律基线：零新依赖；fail-closed；判别值/域标签冻结不动（本任务**零新增
判别值、零字节格式变更**）；poker_l1 全套件 2411 → 2421（+10，零回退）、
poker-appchain 全套件 331 → 340（+9，零回退）、poker-settlement-core
36 → 36（1 例语义改写 + 断言强化，数量不变）。不 git commit。

---

## 1. 语义定稿：计价与处置分层（两侧一致性的根）

TE-E0 留下的开放点（settlement-core `compute_rake` 对 mode 2 显式 Err）
按合约定稿规则落地，决策记录如下（二选一之"实现"分支）：

```text
数量关系（poker-settlement-core，三仓唯一事实源）：
  mode ∈ {1, 2}  →  rake = min(floor(contested_gross · bps / 10⁴), cap, contested_gross)
  mode  = 0      →  rake = 0
  mode ∉ {0,1,2} →  fail-closed 拒（通配臂不变）

资金处置（合约 / appchain admission 的落点，不在 plan 内建模）：
  mode 1（FixedRake）  → TreasurySplit：rake 成 为 treasury/operator 现金输出
  mode 2（FixedRakeBurn）→ Burn：rake 全额销毁，零现金输出（供给紧缩）
```

理由：canonical AIR opening（poker_texas_air `canonical_settlement_rake`）
对 mode ∈ {1, 2} **已证明并冻结同一数量关系**；plan 只编码输出侧切分
（`gross_pot = total_awards + rake`），处置是应用层规则。同一手在 mode 1
与 mode 2 下的 plan 及 digest **逐字节相等**（两侧对照测试钉住：
settlement-core `fixed_rake_burn_prices_identically_to_percentage`、
poker_l1 `burn_and_percentage_plans_match_but_disposals_differ`、
appchain `tests/te_m4.rs::settlement_core_mode2_plan_matches_fee_policy_
and_mode1`）。保持显式 match 臂而非并入 PERCENTAGE：文档化"同式是 TE-M4
定稿决策而非巧合"，未知模式仍走通配 fail-closed。

## 2. 合约侧规则（poker_l1 `vm/contracts/texas_poker/`）

| 落点 | 变更 |
|---|---|
| `constants.rs` | 新增 `RAKE_MODE_FIXED_RAKE_BURN: u8 = 2`（TE-E0 冻结值；与 settlement-core 常量的静态断言钉在 `settlement.rs`） |
| `settlement.rs` | 新增处置规则唯一判定 `rake_disposal(rake_mode, rake_amount) -> RakeDisposal`：`None` / `TreasurySplit{amount}` / `Burn{amount}`；未知模式与 none 模式带正 rake 一律 `Err`（fail-closed） |
| `types.rs` | `TableRules::validate_canonical` 接受 mode 2 开桌配置（bps > 10_000 等既有校验口径不变）；未知模式仍拒 |
| `state_machine.rs` | `compute_rake_amount` / `collect_rake` 文档化 mode 2 计价同式；`collect_rake` 后 `chip_pool` 借记同式——**借记即净销毁**；`RakeCollected` 事件携带 `rake_mode`，下游处置判定无需回读桌配置（事件 ABI 不变，无新变体） |
| `prove_task.rs` | `settlement_treasury_receipt()` 升级为 mode 感知：mode 1 语义逐点不变；mode 2 返回 `None`（不派生 Treasury UTXO）；新增对偶视图 `settlement_rake_burn()`（销毁额 + 锚摘要）；未知 `rake_mode` fail-closed `Err` |

### 2.1 note 表示选择（"不铸即销毁"，已文档化于 `settlement.rs`）

L1 合约的 note 表示是原生 Coin UTXO；burn 处置选择**不铸造** Treasury/
operator coin（而非"铸即焚"）：`apply_settlement_plan` 已把 rake 从
`chip_pool` 借记，precompile escrow 输出经
`settlement_treasury_receipt` 派生——mode 2 无 receipt ⇒ 无 coin 输出 ⇒
TableVault 净值收缩即销毁。TableVault 一致性
（`pre_locked + funding − outputs == post chip_pool`）自动闭合，零
precompile 变更。

### 2.2 诚实降级点（L1 TreasuryCap 计数器）

TreasuryCap（`total_supply/total_minted/total_burned`）的推进调用点
（economics `burn_escrowed_native`）在 `texas_poker_precompile.rs`
（**本任务禁区外**，未改动）：mode 2 桌在 L1 实际结算时，precompile
装配点须在无 Treasury receipt 的 dispatch 输出上调用
`settlement_rake_burn()` 并推进 cap 计数器，否则全局
`reconcile_native_supply` 会出现 `delta = −rake`（健康门暴露，不静默）。
本任务交付的判定视图 + burn 视图使该装配成为纯机械接线。AIR 侧
（poker_texas_air，在飞禁区）对 mode 2 的 opening/计费已在 TE-E0 实测，
处置不在 AIR 建模（`canonical_settlement_rake` 文档原文），无跨层分叉。

## 3. appchain 结算接线（poker-appchain）

### 3.1 v1 / v2 边界（二选一决策：v2 先行，v1 拒 fail-closed）

| 路径 | 行为 | 拒点 |
|---|---|---|
| v1 `Settle` × burn 桌 | **拒** | `validate_settlement` 第 0 条：`"v1 settlement cannot settle a FixedRakeBurn table (burn disposal requires the v2 GAME ledger)"` |
| v2 `SettleV2` × burn 桌 × GAME 注册 token | **放行** | 处置 = burn（见 §3.2） |

理由：(a) GAME 币本就是 v2 账本资产，v1 `NoteSpec` 二元 AssetClass 无法
表达 GAME 注册 token，v1 rake 输出表示不成立；(b) v1 分账路径会把销毁误
当分账入账（`rake_outputs` 对 burn 返回 `(None, None)` 而校验层计 rake
输出——TE-E0 即预见的静默缺口，本任务以显式拒绝关闭）。对照证据：
`tests/te_m4.rs::v1_settlement_on_burn_table_rejected_fail_closed`
（同形态记录换绑 percentage 承诺即通过全部校验）。

### 3.2 v2 结算的 burn 处置（`note_v2::validate_settlement_v2` 最小 match 臂）

- **第 6 条（新增拒绝）**：burn 记录携带 treasury/operator 输出即
  "既入账又销毁"的双计形态 →
  `"fixed rake burn settlement must not carry treasury/operator outputs"`
  （先于资产/守恒检查，诊断精确）；
- **第 7 条（守恒推广）**：burn 桌 `Σinputs == Σpayouts + rake.total`
  （rake.total 是**已销毁的输出侧**）；非 burn 桌销毁额恒 0，等式与既有
  `Σinputs == Σoutputs` 逐点一致（零回退）；
- **第 8 条（分账隔离）**：burn 记录跳过 `split_of` 分账检查（路径隔离）；
- 计价不变：第 5 条费率关系 `rake.total == policy.rake_of(pot)` 对
  burn 同式（TE-E0 冻结），`policy_commitment` 绑定照旧（同参数 burn 与
  percentage 承诺必然不同，注册表冻结不可互混）。

### 3.3 sequencer 准入与应用（`apply_settle_v2`，逐行标注 TE-M4）

- 准入门（检查段）：burn 桌计价资产必须是 **GAME 域已注册 GTS token**
  （`is_game_domain && token_id ≠ 0 && game_registry.contains`）——
  REAL 域误用 burn 策略拒、遗留 PLAY(0) 拒（无 GTS 规格、outstanding
  恒等式不经 Issue 维护）、未注册 token 拒；计
  `game_token_rejected_total` / `game_settle_burn_admitted_total`；
- 应用段（变更段零失败）：`game_burned[token] += rake.total` →
  `game_outstanding = Σminted − Σburned` 收缩 →
  `game_token_outstanding{token}` gauge / `game_settle_burn_amount_total`
  计数。**不铸任何 treasury/operator note**（v1 账本零变化）；
- 双计防线：重放（`settled_bindings` 跨版本共享集）+ 携带输出拒绝
  （§3.2 第 6 条）双重阻断；
- WAL 重放：`game_burned` 经同一 apply 路径重建
  （`tests/te_m4.rs::game_burn_table_one_hand_e2e` 第 7 步逐位断言）。

### 3.4 GAME 域 AssetId 协同（outstanding 对账闭合）

burn 桌一手闭环后恒等式三边核对（INV-TE-7）：

```text
outstanding(token) = Σminted − Σburned == Σ 存续 GAME note 面额
                     ↑ Issue      ↑ BurnGameToken + SettleV2×burn rake
```

e2e 账本变化（GAME 桌一手，`tests/te_m4.rs::game_burn_table_one_hand_e2e`）：

| 步骤 | 账本变化 | outstanding(1) |
|---|---|---|
| RegisterGameToken(1) | 注册表 +1 | 0 |
| IssueGameToken ×2（各 1_000_000） | `game_minted[1] += 2_000_000`，两张 v2 note | 2_000_000 |
| OpenTable(77, FixedRakeBurn 5%) | 注册表冻结 | 2_000_000 |
| SettleV2（pot 2_000_000，alice 独赢） | 消费 2 张 seat 输入 → 铸 1_900_000 payout；`game_burned[1] += 100_000`；treasury/operator 现金 **0** | **1_900_000** |
| 对账 | `consistent == (1_900_000 == live_note_sum)` | ✓ |

v2 seat 生命周期（BuyInV2）未引入（如实声明）：v2 结算输入允许自由余额
note（`validate_settlement_v2` 第 3 条既有语义），故一手以 Issue 铸出的
自由余额 note 直接进入结算，账本口径为 issue → settle → outstanding 收缩。

## 4. 负例清单（全部 fail-closed，`tests/te_m4.rs` + poker_l1 套件）

| # | 负例 | 拒点 | 测试 |
|---|---|---|---|
| N1 | v1 结算 × burn 桌 | validate 第 0 条 | `v1_settlement_on_burn_table_rejected_fail_closed` |
| N2 | burn 记录携带 treasury/operator 输出（双计） | validate_settlement_v2 第 6 条 | `burn_record_carrying_rake_outputs_rejected_no_double_count` |
| N3 | percentage 桌 burn 化（缺分账输出） | 守恒（ConservationViolated） | `percentage_table_burn_shaped_record_rejected_by_conservation` |
| N4 | burn 低报销毁额（99_999 ≠ 100_000） | 费率关系（FeeMismatch） | `burn_under_reported_rake_rejected_by_fee_relation` |
| N5 | burn 结算重放（outstanding 二次收缩） | SettlementReplay | `burn_settlement_replay_rejected_outstanding_unchanged` |
| N6 | REAL 域误用 burn 策略 | sequencer GAME 域门 | `burn_policy_requires_registered_game_domain_token` (a) |
| N7 | 未注册 GAME token（game(999)） | sequencer GAME 域门 | 同上 (b) |
| N8 | 遗留 PLAY(0) burn 桌 | sequencer GAME 域门 | `burn_policy_rejects_legacy_play_token` |
| N9 | 未知 rake 模式（L1 处置视图） | `rake_disposal` Err | poker_l1 `prove_task::none_mode_is_quiet_and_inconsistent_or_unknown_modes_fail_closed` |
| N10 | none 模式带正 rake 的 receipt | `rake_disposal` Err | 同上 |
| N11 | 未知模式开桌配置（TableRules） | validate_canonical Err | poker_l1 `table_rules_accept_fixed_rake_burn_and_reject_unknown_modes` |

## 5. 测试证据与计数

| 套件 | 基线 | 现状 | 差额 |
|---|---|---|---|
| poker_l1（--release 全套件） | 2411 | **2421**（0 failed） | +10：settlement.rs 4（burn 守恒 / 处置对照 / mode 0-1 零回退 / 跨 crate burn 对照）+ types.rs 1（开桌配置）+ state_machine.rs 1（mode 2 计价同式）+ prove_task.rs 4（burn 视图 / mode 1 零回退 / fail-closed / uncontested burn） |
| poker-appchain（--release 全套件） | 331 | **340**（0 failed） | +9：`tests/te_m4.rs`（e2e 一手 + v1/v2 边界 + 负例矩阵 + 两侧一致性 + WAL 重放） |
| poker-settlement-core（--release） | 36 | **36**（0 failed） | `fixed_rake_burn_mode_is_fail_closed_in_derivation` 改写为 `fixed_rake_burn_prices_identically_to_percentage`（TE-M4 定稿语义；含未知模式通配拒绝回归） |

两侧一致性对照（计价同式的三重钉扎）：settlement-core 与 poker_l1 对同一
mode 2 手的 plan/digest 逐字节相等；appchain 侧 `plan.rake ==
policy.rake_of(rake_base)` 费率关系对 mode 2 成立（与 mode 1 同式）。

## 6. 边界与降级（如实声明）

1. **canonical AIR 出证路径不可达**：burn 桌归档出证需 texasair 适配器
   管线；AIR 侧 opening 对 mode 2 的计费数量关系已在 TE-E0 实测
   （`canonical_settlement_rake` mode ∈ {1,2} 同式），故本任务交付为
   host 级 e2e（GAME 桌一手账本闭环）。
2. **L1 TreasuryCap 计数器装配**（§2.2）：precompile 在禁区外，交付
   mode 感知视图 + burn 视图，装配点接线为后续机械步骤；未接线时由
   全局供给对账健康门暴露（不静默）。
3. **v2 seat 生命周期（BuyInV2）**：未引入（见 §3.4）；GAME 桌一手以
   自由余额 note 直接结算（既有 v2 语义，无放宽）。
4. **te_m2 尾注更正**：该文件头注"GAME 桌 / FixedRakeBurn（TE-M4）属
   边界不在此测试"自本任务起由 `tests/te_m4.rs` 兑现；`tests/game_token.rs`
   头注同。
