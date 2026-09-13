# ABI TE-M6：Free 模式 gas 服务费（排期表 §6 TE-M6）

状态：**已实现**（poker-appchain）。设计依据 `docs/plan-token-economy-v1.md`
§3.8（FREE 模式：免购买 + gas 服务费）、§4.1（收入属性：无储备义务）、
§5（协议层强制点 9/10）、TE-D7（Paid 桌叠加收费 v1 禁止）。前置：TE-M3
（`docs/ABI_TE_M3.md`，判别值 14/15/16 预留）、TE-M4（GAME 桌
`FixedRakeBurn`，gas 门与 burn 处置并存已实测）。

纪律基线：零新依赖；fail-closed；既有测试零回退（appchain 基线全绿，
新增 `tests/te_m6.rs` 16 用例 + `game_token.rs` 单元 3 用例，只增不减）；
borsh 只追加（判别值 14/15/16 末位追加，旧字节流解码兼容）。

---

## 1. Operation 判别值（additive，末位追加；**冻结**）

| 判别值 | 变体 | 载荷 | 阶段 |
|---|---|---|---|
| 0..=6 | v1 冻结（OpenTable/CloseTable/Deposit/WithdrawRequest/Transfer/BuyIn/Settle） | — | 不变 |
| 7..=10 | v2 / TE-M2（MigrateNote/SettleV2/DepositV2/WithdrawRequestV2） | docs/ABI_V2.md、ABI_TE_M2.md | 不变 |
| 11..=13 | TE-M3（RegisterGameToken/IssueGameToken/BurnGameToken） | docs/ABI_TE_M3.md | 不变 |
| **14** | **`FaucetMint(Box<FaucetMintOp>)`** | 见 §1.1 | TE-M6 |
| **15** | **`BuyGasCredits(Box<BuyGasCreditsOp>)`** | 见 §1.2 | TE-M6 |
| **16** | **`BindGasPolicy(Box<BindGasPolicyOp>)`** | 见 §1.3 | TE-M6 |
| 17（预留） | 后续变体只能 ≥ 17 追加 | — | — |

判别值 = 声明序（borsh）；**14/15/16 冻结**。`Box` 仅 Rust 侧布局优化，
borsh 编码与裸结构一致（与 7..=13 同纪律）。三变体均为 **operator 帧**
（`spends()` 空、`effect_digest()` 为零摘要，同 `DepositV2`/
`RegisterGameToken` 纪律；限流归 operator principal）。负例回归：
`tests/te_m6.rs::ops_discriminants_frozen_te_m6` 钉住首字节 14/15/16 与
TE-M3 判别值 13 不受追加影响。穷举 match 的机械追加（既定先例，TE-M6
注明）：`archive_index.rs::kind_of` 与 `bin/explorer_gateway/api.rs::
op_type_name` 各补三臂（"FaucetMint"/"BuyGasCredits"/"BindGasPolicy"，
双处拼写一致）。

### 1.1 `FaucetMintOp`（判别值 14）

```text
FaucetMintOp := {
    claim_id: [u8; 32],   # 领取幂等键（op 族内查重）
    token_id: u32,        # 目标游戏币（已注册 GTS token 且 Free 模式）
    owner: OwnerRef,      # 领取人（铸出 note 的 owner）
    amount: u64,          # 申请铸造量（> 0）
}
```

语义：Free token 的**专属领取通道**——无外部支付（不销售，合规定性见
设计 §3.8.1：币刻意不稀缺）。限量按 genesis 冻结的 `FaucetPolicy` 强制：
`amount ≤ single_max` 且终身累计 `≤ player_lifetime_max`（按
`owner_commitment` 记账；超限 `RateLimited`，计 `faucet_rate_limited_total`
）。Paid token 走本 op 拒（两通道互斥——Paid 铸造是 `IssueGameToken`）；
遗留 PLAY(0) 拒；`max_supply` 与 Issue 同口径（`SupplyCapExceeded`）。
铸 GAME 域自由余额 v2 note（nonce = `mint_nonce_v2(b"faucet-mint",
claim_id)`）。供给恒等联动：`game_minted` / `game_faucet_issued` /
outstanding gauge（INV-TE-7 不变）。

### 1.2 `BuyGasCreditsOp`（判别值 15）

```text
BuyGasCreditsOp := {
    pay_digest: [u8; 32],       # 外部支付幂等键
    payer: OwnerRef,            # 付款人（credit 记账身份 = owner_commitment）
    pricing_asset_id: AssetId,  # 计价资产（REAL 域已注册 token）
    pay_amount: u64,            # 支付额（计价资产最小单位；> 0）
}
```

语义：REAL 域计价外部支付 → credit 额度 **1:1 入账**（`pay_amount`
最小单位 == credit 单位，与 `GasPolicy::fee_per_hand` 同量纲；1e18 展示
刻度属部署/呈现面）。幂等：`pay_digest` op 族查重 + **跨路径前向查重**
（v1 `deposit_ids` / v2 `deposit_records_v2` / GAME `game_issue_ids` 任一
命中即拒——同一外部支付不得既走托管存款/发行又走服务费收入）。反向
防线（deposit/issue 侧不反查 gas 摘要集）由 watcher 支付确认幂等承担，
如实声明。GAME 域 / 伪造 REAL token 计价拒（fail-closed 封闭枚举门）。

**credit 账本语义（非储备声明，§2）与 INV-TE-8 见 §2/§3。**

### 1.3 `BindGasPolicyOp`（判别值 16）

```text
BindGasPolicyOp := {
    table_id: u64,        # 目标桌（必须已 OpenTable 且开放）
    token_id: u32,        # 桌 GAME token（已注册且 Free 模式）
    policy: GasPolicy,    # { fee_per_hand, pricing_asset_id, min_coverage_k }
}
```

语义：GAME 桌绑定桌级 gas 策略——**绑定即冻结**（重绑拒，同 FeePolicy
开桌冻结纪律）；排序（设计 §3.8.2）：`OpenTable` 之后、首次买入/结算
受理之前。准入：

1. 桌门（未开放/不存在 → `TableNotOpen`）；
2. token 门：**Paid 模式 token 拒（TE-D7：双重收费 v1 禁止，放开 =
   治理项）**；遗留 PLAY(0) / 未注册 token 拒（PLAY 永久免费层，永不
   商业化）；
3. 结构门（[`GasPolicy::new`]）：`fee_per_hand > 0`、
   `min_coverage_k ≥ 3`（`GAS_MIN_COVERAGE_K` 冻结下限）、计价资产 REAL
   域已注册 token（NATIVE/USDT/USDC 封闭枚举；GAME 域拒——服务费必须
   真实价值资产计价）；
4. **成本覆盖**：`fee_per_hand ≥ min_coverage_k × c_hand`（u128 中间量）
   ——`c_hand` 由 `SequencerConfig::gas_c_hand_estimate` 注入，是**运营
   参数**（每手摊薄成本 = (结算 gas + 证明成本 + 基础设施) / 预期手数，
   真实计量属部署面 B-TE-2 同源；默认 0 = 覆盖强制未激活的诚实缺省）。
   不足拒（`GasPolicyRejected`，计 `gas_coverage_rejected_total`）。

固定费额，刻意**不与底池挂钩**：底池比例费形似对 wager 抽水，损害
"服务费"定性；固定费 = 与胜负无关的服务定价（设计 §3.8.2）。设计文档
中 `GasPolicy.split`（FeeSplit 分账）v1 不做——credit 消耗只进计量账，
收入分账属运营审计层（如实降级点）。

---

## 2. gas credit 账本语义（[`GasCreditLedger`]；**非储备声明**）

```text
credit(owner, currency) := Σpurchased − Σconsumed      # 逐玩家逐币种
```

- **credit 是账面额度，不是链上资产**：不铸 note（无承诺、无 nullifier、
  不进任何 Merkle 树/状态根）；
- **不进 CustodyLedger 对账恒等式**：`delta[code] = reserved − issued
  == 0` 的两边都不含 gas 服务费收入——它是**已售服务额度**（收入，无
  赎回、无储备义务），不是玩家余额、不是协议负债。本隔离是**物理性**
  的：计量账与托管账是两套互不引用的状态（`LedgerState.gas_credits` vs
  vault/CustodyLedger 输入 `issued_v2_real_by_token` / `burned_v2`），
  测试 `gas_credits_do_not_pollute_custody_identity` 钉住 credit 全流程
  （购买/绑定/扣费）前后托管恒等式输入逐位不变；
- 账本态不入状态根，WAL 重放经 apply 路径逐位重建（与 `game_registry`
  同纪律）；导出格式标签 `zchain.game_token.gas_credit.v1`（JSON：
  format / reserve_note="NOT reserve" / invariant_holds / 逐 asset 汇总
  / 逐 (owner, asset) 余额；u128 十进制字符串）。

## 3. 不变量（fail-closed，全部拒绝路径计 metric）

| # | 不变量 | 强制点 | metric / 错误 |
|---|---|---|---|
| INV-TE-8 | credit 逐玩家逐币种 ≥ 0：消耗前置校验，不足整笔拒（零状态变更；负余额由 u64 + checked 算术结构上不可表达） | SettleV2 受理检查段（`ensure_spendable`），扣减在受理段 | `gas_credit_insufficient_total` / `GasCreditInsufficient{asset, balance, required}` |
| INV-TE-9 | Free 模式 token 的结算出现在**未绑定**（或绑定 token 不匹配的）桌 → 受理拒绝 | `apply_settle_v2` TE-M6 门（判定键 = 首输入资产 token） | `gas_policy_missing_rejected_total` / `AdmissionRejected("...bound gas policy...")` |
| 成本覆盖 | `fee_per_hand ≥ min_coverage_k · c_hand`（k ≥ 3 冻结） | BindGasPolicy 准入（绑定时刻） | `gas_coverage_rejected_total` / `GasPolicyRejected` |
| TE-D7 | Paid 模式 token 桌绑定 GasPolicy 拒；Paid 桌结算零 gas 扣减 | BindGasPolicy 准入 + SettleV2 门（仅 Free token 触发） | `gas_policy_rejected_total` / `GasPolicyRejected("TE-D7...")` |

### 3.1 消耗语义（Free 桌每手结算）

- 判据：SettleV2 首输入资产为 GAME 域**已注册且 Free 模式**的 GTS
  token（遗留 PLAY(0) / REAL 域 / Paid token 永不触发）；
- **发起方 = 首输入 note 的 owner**（v2 输入；GTS token 只在 v2 账本
  存在，结构上必为 V2 臂——V1 臂兜底 fail-closed 拒）；
- 受理前校验发起方 `credit ≥ fee_per_hand`；受理（全部校验通过、进入
  变更段）即扣减——**固定费额，与 pot/胜负/rake 无关**（同一桌不同
  底池每手扣减相同）；
- **结算守恒不动、AIR 零改动**：gas 是准入控制 + 计量，不进结算记录、
  不进 pot 数学——结算仍单资产守恒（INV-TE-5）；game_outstanding /
  INV-TE-7 不受 credit 活动影响；
- 校验段 `ensure_spendable` 与受理段 `spend` 之间零状态变更（C1 纪律）
  ——扣减在受理段不可失败。
- 边界（如实声明）：INV-TE-9 的"首次买入拒绝"强制点落在 SettleV2
  受理——v2 seat 生命周期（BuyInV2）未引入（TE-M4 同款边界），Free
  token 进入桌生命周期的首个受理点即结算；BuyInV2 落地时必须镜像本门。
  v1 路径（`apply_settle` / `apply_buy_in`）零变更：v1 note 只能是遗留
  资产（REAL/PLAY token 0），永不触发 Free 门。

## 4. 指标增量（设计 §6）

```text
ops_faucet_mint_total / ops_buy_gas_credits_total / ops_bind_gas_policy_total
faucet_mint_total / faucet_rate_limited_total            # TE-M3 已建沿用
gas_credits_purchased_total                              # Σ 面额
gas_credits_purchased_total{currency="real:native|usdt|usdc"}
gas_credits_consumed_total（+ {currency} 标签变体）
gas_credit_balance{currency}                              # gauge（Σ 余额）
gas_policy_bound_total / gas_policy_rejected_total
gas_policy_missing_rejected_total / gas_credit_insufficient_total
gas_coverage_rejected_total
```

## 5. 边界（如实声明，不在此实现）

- **真实 c_hand 计量属部署面**：`gas_c_hand_estimate` 是运营注入的估算
  参数（默认 0 = 覆盖强制未激活；生产必须显式注入并全网一致——变更须
  同步所有重放方，与 `game_rate_min/max` 同纪律）；
- **每手费用/计价币种的 UI 呈现属 TE-M5 面**（消费者定价披露，设计
  §3.8.4）；链上只承载费额与计价资产的协议事实；
- **时间窗限流**（每玩家单位时间上限）v1 不做：faucet 限量 = single_max
  + player_lifetime_max 双上限，弱于设计 §3.8.3 最终口径；
- **FeeSplit 分账**（设计 §3.8.2）v1 不做：credit 消耗只进计量账，收入
  分账属运营/审计层；
- KYC 身份作为 faucet 限流键（设计 §3.8.3）属部署/合规面——链上限流键
  为 `owner_commitment`；
- credit 无赎回：封闭操作集无退回变体（结构性保证，与 GAME 单向性同源）。

## 6. 测试证据（`tests/te_m6.rs`，16 用例，--release 全绿）

| 用例 | 覆盖 |
|---|---|
| `ops_discriminants_frozen_te_m6` | 14/15/16 冻结 + TE-M3 判别值不受影响 + roundtrip |
| `faucet_mint_enforces_single_and_lifetime_limits` | 单次/终身限量、RateLimited、通道互斥、PLAY 拒、零面额、INV-TE-7 |
| `faucet_mint_claim_id_idempotent_and_supply_cap` | claim_id 幂等零状态变更、SupplyCapExceeded、owner 隔离 |
| `buy_gas_credits_books_balance_and_is_idempotent` | 1:1 入账、digest 幂等、跨路径前向查重（deposit/issue）、结构门、币种/owner 隔离 |
| `bind_gas_policy_happy_path_and_frozen` | 绑定正例 + 重绑拒（冻结） |
| `bind_rejects_paid_token_play_and_unregistered_te_d7` | TE-D7 / PLAY / 未注册 / 桌门 |
| `bind_rejects_bad_policy_structure` | 零费 / k<3 / GAME 计价 / 伪造 REAL 计价 |
| `cost_coverage_enforced_at_bind_time` | `fee ≥ k·c_hand` 边界（2999 拒 / 3000 过）+ c_hand=0 诚实缺省 |
| `free_table_settle_without_binding_rejected_inv_te9` | INV-TE-9 + 拒绝零状态变更（root 不变、binding 未烧） |
| `free_table_settle_with_binding_deducts_fixed_fee` | 绑定后扣费、固定费额与底池无关（200/300 两手同扣 10）、INV-TE-8 恒等 |
| `free_table_settle_insufficient_credit_rejected_inv_te8` | INV-TE-8 不足拒 + 零状态变更 + 补足后同手受理 |
| `free_table_binding_token_mismatch_rejected` | 绑定 token ≠ 结算 token → INV-TE-9 拒 |
| `paid_token_table_settle_unaffected_by_te_m6` | Paid 桌零 gas 门（TE-D7 语义） |
| `free_table_on_burn_policy_charges_gas_and_burns_rake` | gas 门 × TE-M4 burn 处置并存（outstanding 收缩 + credit 扣减） |
| `gas_credits_do_not_pollute_custody_identity` | **托管隔离**：REAL issued / burned_v2 / REAL live 面额逐位不变；导出非储备声明 |
| `wal_replay_restores_gas_ledger_bindings_and_faucet_ids` | WAL 重放逐位恢复 credit 账本 / gas 绑定 / faucet 幂等集；幂等集恢复生效 |

单元测试（`src/game_token.rs`，+3）：`gas_policy_new_validates_structure_
fail_closed`、`gas_policy_cost_coverage_k_times_c_hand`、
`gas_credit_ledger_credit_is_idempotent_and_per_asset`、
`gas_credit_ledger_spend_enforces_non_negative_invariant`。
