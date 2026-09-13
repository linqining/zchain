# ABI TE-M3：GTS 游戏币标准（排期表 §6 TE-M3）

状态：**已实现**（poker-appchain）。设计依据 `docs/plan-token-economy-v1.md`
§3（GAME 代币标准）、§3.2（发行价带 INV-TE-4）、§3.3/§3.4（单向与不可桥
INV-TE-3）、§4.3（对账矩阵）、§5（协议层强制点 3/4/5）。前置：TE-M1
（`AssetId`，`docs/ABI_ASSET_ID.md`）、TE-M2（`docs/ABI_TE_M2.md`，
`DepositV2` 拒 GAME 域的先例）。

纪律基线：零新依赖；fail-closed；既有测试零回退（appchain 基线 306 →
331，只增不减：新增 `tests/game_token.rs` 20 用例 + `game_token.rs` 单元
5 用例）；borsh 只追加（判别值 11/12/13 末位追加，旧字节流解码兼容）。

---

## 1. Operation 判别值（additive，末位追加）

| 判别值 | 变体 | 载荷 | 阶段 |
|---|---|---|---|
| 0..=6 | v1 冻结（OpenTable/CloseTable/Deposit/WithdrawRequest/Transfer/BuyIn/Settle） | — | 不变 |
| 7 | `MigrateNote(Box<MigrateNoteOp>)` | docs/ABI_V2.md | v2 |
| 8 | `SettleV2(Box<SettlementRecordV2>)` | docs/ABI_V2.md | v2 |
| 9 | `DepositV2(Box<DepositV2Op>)` | docs/ABI_TE_M2.md | TE-M2 |
| 10 | `WithdrawRequestV2(Box<WithdrawRequestV2Op>)` | docs/ABI_TE_M2.md | TE-M2 |
| **11** | **`RegisterGameToken(Box<RegisterGameTokenOp>)`** | 见 §1.1 | TE-M3 |
| **12** | **`IssueGameToken(Box<IssueGameTokenOp>)`** | 见 §1.2 | TE-M3 |
| **13** | **`BurnGameToken(Box<BurnGameTokenOp>)`** | 见 §1.3 | TE-M3 |
| 14（预留） | `FaucetMint` | TE-M6（Free 模式完整机制） | 未实现 |
| 15（预留） | `BuyGasCredits` | TE-M6（gas credit 计量账） | 未实现 |
| 16（预留） | `BindGasPolicy` | TE-M6（桌级 GasPolicy） | 未实现 |

判别值 = 声明序（borsh）；**11/12/13 冻结**，TE-M6 变体从 **14** 起后续
排（设计 §8 TE-M6 行；本任务不实现、不占位结构）。`Box` 仅 Rust 侧布局
优化，borsh 编码与裸结构一致（与 7..=10 同纪律）。负例回归：
`tests/game_token.rs::borsh_discriminants_frozen_and_op_shape` 钉住首字节
11/12/13 与 v1/v2 判别值不受追加影响。穷举 match 的机械追加（既定先例，
TE-M3 注明）：`archive_index.rs::kind_of` 与
`bin/explorer_gateway/api.rs::op_type_name` 各补三臂
（"RegisterGameToken"/"IssueGameToken"/"BurnGameToken"，双处拼写一致）。

### 1.1 `RegisterGameTokenOp`（判别值 11）

```text
RegisterGameTokenOp := {
    token_id: u32,             # GAME 域 AssetId.token_id；0 = 遗留 PLAY 保留位（拒）
    issuer: [u8; 33],          # 发行方公钥（v1 = 平台运营方，TE-D3；非零）
    mode: IssuanceMode,        # Paid{anchor, rate} | Free{faucet}（borsh 判别 Paid=0/Free=1）
    max_supply: u64,           # 0 = 不限；Σminted ≤ max_supply 由 sequencer 强制
    genesis_digest: [u8; 32],  # 客户端预计算；链侧重算必须全等
}
```

语义：operator/发行方 genesis 登记（watcher 外驱动的 operator 帧——
`spends()` 空、效果摘要为零，同 v1 Deposit 纪律）。**注册即冻结**：
同 token_id 重注册一律拒（含改 rate 的"重定价"载荷）——**重定价 =
发新 token**（TE-D2），旧 token 自然消亡。准入顺序（`apply_register_
game_token`，C1 纪律）：规格结构校验（token 0 保留位 / 零 issuer /
anchor REAL 域封闭枚举 / rate > 0 / faucet 参数）→ genesis 摘要全等
→ 价带校验（§3，计 `issuance_rate_rejected_total`）→ 注册位查重。

### 1.2 `IssueGameTokenOp`（判别值 12）

```text
IssueGameTokenOp := {
    issue_id: [u8; 32],        # 外部支付幂等键（跨路径查重，见 §4）
    token_id: u32,             # 目标游戏币（必须已注册；PLAY(0) 拒）
    buyer: OwnerRef,           # 买家（v2 owner 引用；铸出 note 的 owner）
    pay_amount: u64,           # Paid：anchor 1e18 wei 支付额；Free：申请铸造量
}
```

语义：**GAME 域唯一入口**。外部支付 anchor → watcher 按 `issue_id` 幂等
确认 → operator 提交本 op → 铸 GAME 域自由余额 v2 note（table=None、
pot/runout=0；nonce = `blake2s32("issue-game" || seq_be || issue_id)[..8]`
截断 u64）。发行支付**全额进协议金库**，不退回、不分给发行方（v1；
TE-D3）。operator 帧（spends() 空、效果摘要为零，同 `DepositV2`）。

铸造公式（Paid，设计 §3.1 冻结）：

```text
mint = floor(pay_amount_e18 * R / 1e18)      # u128 中间量，向下取整
mint == 0 → 拒（尘埃支付：不足 1 币全额留在未铸侧，无零面额 note）
```

正例（`tests/game_token.rs::paid_issue_floor_formula_exact_on_chain`）：
R = 1_000_000（1U = 100 万币）时 pay 1e18 → 恰 1_000_000 币；
pay 1e18 + 1 wei → 仍 1_000_000 币（1 wei 尘埃截断）；
R = 3、pay 1.5e18 → 4（4.5 floor）。

Free 模式骨架（TE-M3 边界，见 §8）：`pay_amount` 按申请量直铸，受
faucet 限量强制——单次 ≤ `single_max`、每玩家（owner_commitment 键）
终身累计 ≤ `player_lifetime_max`，超限 `RateLimited` + 计
`faucet_rate_limited_total`。**时间窗限流 / gas 服务费 / FaucetMint
独立 op 属 TE-M6，本任务不做**（骨架限流弱于最终口径，Free 模式生产
启用前必须等 TE-M6，如实声明）。

### 1.3 `BurnGameTokenOp`（判别值 13）

```text
BurnGameTokenOp := {
    burn_id: [u8; 32],             # 销毁幂等键（op 族内查重）
    token_id: u32,                 # 必须 == note.asset_id.token_id 且已注册
    note: NoteV2,                  # 被销毁 v2 note 全量内容（账本核对）
    nullifier: [u8; 32],           # 声明消费 nullifier（非零，进共享集）
    owner_sig: SignatureEnvelope,  # v2 信封（owner_v2 验签，BURN_GAME scope）
    material: VerifierMaterial,    # 验签材料（随载荷；WAL 重放全量复核）
}
```

语义：**GAME 域唯一出口**——rake 回收（TE-M4 `FixedRakeBurn` 前的主动
销毁通道）与玩家销毁共用。授权管线镜像 `WithdrawRequestV2`（11 步准入，
`apply_burn_game_token`），scope 换用 `burn_game.v2`：

```text
scope  = spend_scope(network_id, OWNER_V2_ABI_VERSION, "burn_game.v2")
effect = blake2s32("effect.burn_game.v2", burn_id, token_id_be,
                   note.commitment, nullifier)
digest = v2_spend_digest(owner, note.commitment, nullifier, scope, effect)
owner_sig.typed_data_digest == digest       # 否则 digest mismatch
```

**REAL 域拒入本 op（对称纪律，fail-closed + 计数）**：note 非 GAME 域
→ `AdmissionRejected("burn accepts GAME domain tokens only")` + 计
`game_token_rejected_total`——REAL 资产出口是 Withdraw/WithdrawV2，两
通道互斥。遗留 PLAY(0) 无 GTS 规格（注册表无 1 号项），拒入本 op；
token_id 声明与 note 资产不一致拒。

## 2. GTS 结构与冻结语义（`game_token.rs`）

```text
GameTokenSpec := {
    token_id: u32,             # GAME 域 token id（0 = PLAY 保留位）
    issuer: [u8; 33],          # 发行方公钥
    mode: IssuanceMode,        # Paid{anchor: AssetId, rate: u64} | Free{faucet: FaucetPolicy}
    max_supply: u64,           # 0 = 不限
    genesis_digest: [u8; 32],  # 全字段绑定
}

IssuanceMode（borsh 判别值冻结：Paid=0 / Free=1；TE-M6 只能尾部追加）
FaucetPolicy := { single_max: u64, player_lifetime_max: u64 }   # TE-M3 骨架口径
```

`genesis_digest = blake2s32("zchain.game_token.genesis.v1",
borsh((token_id, issuer, mode, max_supply)))`——**全部字段绑定**（含
anchor 币种与 rate；任何字段篡改必得不同摘要）。诚实声明：任务口径的
"blake2b" 落地为 crate 规范 32B 哈希 `keys::blake2s32`（blake2 家族
blake2s-256，零新依赖）；设计 §3.1 的 poseidon 口径由 AIR 层接线时对齐
同一 32B 摘要（domain 标签 `zchain.game_token.genesis.v1` 冻结）。

`GameTokenRegistry`（token_id → spec，BTreeMap 确定序）：注册位一次性
（append-only，重注册拒）。发行/销毁入口必须经
`AssetDomain::Game.is_registered_token_in(token_id, registry)`
（`asset_id.rs` 预留的 `is_registered_token` 扩展点的注册表感知形式；
TE-M3 唯一扩展点，纯追加，静态谓词 `is_registered_token` 语义不变）。

## 3. 发行价带（INV-TE-4，双层强制）

```text
R = 每 1e18 wei anchor 可铸游戏币数（rate 语义，设计 §3.1 冻结；
    未采用 rate_num/rate_den 分数形式——设计文档为整型 R 口径）
R ∈ [R_min, R_max]（闭区间；治理参数，SequencerConfig.game_rate_min/max 注入）
默认：R_min = 1e5，R_max = 1e7（设计 §3.2 参考值；R_max 依据成本覆盖
    推导 1/(k·c)，k ≥ 5；真实成本复核 B-TE-2）
```

1. **validation 层**：注册时 `rate ∉ [R_min, R_max]` →
   `RateOutOfBand{rate, min, max}`，计 `issuance_rate_rejected_total`
   （负例：99_999 与 10_000_001 双向拒，边界值过）。
2. **AIR/承诺层**：rate 进 `genesis_digest`（全字段绑定）——带外 rate
   的发行 witness 不可证明（AIR 公共输入接线属证明层，本层摘要已钉住）。

边界（如实声明）：价带参数是**全网一致参数**——重放方配置不一致时，
边界注册的 WAL 重放状态根分叉（fail-closed 暴露，与 network_id 同纪律）。
Free 模式无 rate，不涉价带（其成本覆盖是 gas 服务费定价，TE-M6）。

## 4. 单向封闭与幂等命名空间

- **入口唯一**（`IssueGameToken`）/ **出口唯一**（`BurnGameToken`）；
  封闭 op 集无 "GAME → anchor" 变体、无跨链变体——不可兑换/不可桥是
  结构性质（设计 §3.3/§3.4），任何人（含运营方）无法在协议内构造。
- **REAL ↔ GAME 双向拒**（对称纪律 + 计数）：

| 通道 | GAME 域 | REAL 域 |
|---|---|---|
| `DepositV2`（TE-M2） | 拒（既有断言保持）+ 计数 | 放行（REAL 域封闭枚举） |
| `WithdrawRequestV2`（TE-M2） | 拒 + `game_withdraw_rejected_total` | 放行 |
| `IssueGameToken`（TE-M3） | 放行（已注册 GTS token） | 结构性不可表达（铸出恒为 `AssetId::game`）；anchor 域合法性在注册面强制 |
| `BurnGameToken`（TE-M3） | 放行（已注册 GTS token） | 拒 + 计数 |

- **幂等命名空间**（`issue_id` 跨路径）：

```text
game_issue_ids ∋ issue_id ⇒ 拒（族内重放）
deposit_ids ∋ issue_id ⇒ 拒（v1 Deposit 已用同一外部支付）
deposit_records_v2 ∋ issue_id ⇒ 拒（v2 DepositV2 已用）
反向：DepositV2 的 deposit_id 命中 game_issue_ids ⇒ 拒
     （v1 Deposit 路径冻结不动，反向防线由 v2/GAME 侧承担——TE-M2 同款分工）
burn_id：game_burn_ids 族内查重（本地授权键，不涉外部支付，无跨族语义）
```

## 5. 供给恒等（INV-TE-7）与日终对账

```text
outstanding(token) = Σminted − Σburned == Σ 存续 GAME note 面额
```

- 聚合账：`LedgerState.game_minted / game_burned`（per-token，u128）；
  查询 `LedgerState::game_outstanding(token_id)`。
- 日终对账：`LedgerState::game_reconciliation()`（逐 token 三边核对，
  `consistent == (outstanding == live_note_sum)`，`live_note_sum` 对
  `notes_v2` 全量扫描）→ `game_reconciliation_json()` 导出。
  导出样例（`tests/game_token.rs::reconciliation_json_export_shape`）：

```json
{"all_consistent":true,"format":"zchain.game_token.reconciliation.v1",
 "tokens":[{"burned_total":"1000000","consistent":true,"live_note_sum":"0",
            "minted_total":"1000000","outstanding":"0","token_id":1}]}
```

（u128 以十进制字符串表达，避免 JSON 数值精度歧义；键序为
`serde_json::json!` 字母序，读取方按名读取。任何 `consistent == false`
即账本 bug 信号，日终告警。）

## 6. 账本态与状态根边界（如实声明）

TE-M3 的 GAME 账本态（注册表 / `game_issue_ids` / `game_burn_ids` /
`game_minted` / `game_burned` / `game_faucet_issued`）**不入状态根**——
与 TE-M2 `deposit_records_v2` 同纪律：WAL 重放经同一 `apply_op` 路径
逐位重建（`tests/game_token.rs::wal_roundtrip_restores_registry_and_
outstanding` 钉住：root 逐位一致 + 注册表/聚合/幂等集恢复 + 重放后
幂等/冻结语义保持）。取舍：零改动状态根公式（v2 折叠段顺序冻结不动，
既有链零影响）；后续若需要把注册表承诺进状态根，属 ABI 版本升级
（v2 折叠段尾部追加）。

## 7. 指标增量（M9 惯例；MetricsRegistry 平面名，无 label 机制——
per-token 量以名内嵌 label 表达）

```text
game_token_registered_total               # 注册成功数
game_token_minted_total                   # 发行笔数
game_token_minted_amount_total            # 发行面额累计
game_token_burned_total                   # 销毁笔数
game_token_burned_amount_total            # 销毁面额累计
game_token_outstanding{token="<id>"}      # gauge（发行/销毁后刷新）
game_token_rejected_total                 # GAME↔REAL 边界拒入计数族
game_withdraw_rejected_total              # GAME 域提现拒（应恒 0，非零即审计信号）
issuance_rate_rejected_total              # 价带越界拒
faucet_rate_limited_total                 # Free 骨架限量拒
ops_game_register_total / ops_game_issue_total / ops_game_burn_total
```

## 8. 边界（如实声明）

1. **Free 模式完整机制属 TE-M6**：时间窗限流（每玩家单位时间上限）、
   `GasPolicy`/`BindGasPolicy`、gas credit 计量账（`BuyGasCredits`）、
   `FaucetMint` 独立 op（判别值 14+ 预留）。TE-M3 只有注册 + 限量铸造
   骨架（单次 + 终身上限）；**gas 服务费不实现**。
2. **重定价 = 发新 token**（TE-D2）：注册位一次性，无任何改 rate 路径；
   重注册（同 id 同/异载荷）一律拒。
3. **链上支付通道属部署面**：anchor 收款地址/合约白名单、watcher 支付
   确认的通道实现、KYC 界面（B-TE-3）不在本任务；协议内只有
   `issue_id` 幂等铸币语义。
4. **GAME 桌属 TE-M4**：GAME 域开桌入口、`FixedRakeBurn`（rake 即销毁）、
   GAME 分区存储。本任务的 GAME note 均为自由余额形态。
5. **AIR 层接线属证明层**：价带公共输入、genesis 承诺进 AIR 约束——
   本层以 genesis 摘要钉住全部字段，witness 不可证明性由后续证明
   接线兑现（与 TE-M1/TE-M2 的 AIR 边界同口径）。
6. **注册表 JSONL 持久化（设计 §3.7）**：链内注册表是 WAL 重放重建的
   账本态（§6）；append-only JSONL 存储属运营/watcher 侧持久化，部署
   阶段落（沿 bond.rs 纪律）。
7. **anchor 币种白名单**：本层只强制 REAL 域封闭枚举（NATIVE/USDT/USDC）；
   TE-D4 的"仅稳定币起步"是治理面约束，不进协议。
8. **哈希原语**：genesis 摘要用 blake2s-256（crate 规范，零新依赖），
   见 §2 诚实声明。

## 9. 测试证据（`tests/game_token.rs` 20 用例 + `game_token.rs` 单元 5 用例）

| # | 用例 | 覆盖 |
|---|---|---|
| 1 | `register_is_frozen_and_reregistration_rejected` | 注册冻结 / 重注册拒（同/异载荷）/ 重定价 = 新 token |
| 2 | `register_rejects_reserved_slot_and_bad_payloads` | PLAY 保留位 / GAME anchor / 零 issuer |
| 3 | `genesis_digest_tamper_rejected` | 摘要失配拒（全字段绑定） |
| 4 | `rate_band_out_of_bounds_rejected_with_metric` | 价带上下界拒（99_999 / 10_000_001） |
| 5 | `rate_band_edges_accepted` | 边界值过 + 自定义治理带 |
| 6 | `paid_issue_floor_formula_exact_on_chain` | floor 公式（1U=100 万币 / 1 wei 尘埃 / 4.5→4） |
| 7 | `issue_dust_payment_rejected` | 尘埃支付拒、零状态变更 |
| 8 | `issue_idempotent_within_family_and_cross_path` | 族内 + 跨路径（v1/v2 Deposit 双向）幂等 |
| 9 | `issue_rejects_unregistered_and_play_slot` | 未注册 / PLAY(0) 拒入发行 |
| 10 | `max_supply_cap_enforced` | 恰满放行 / 超限拒（无部分铸造）/ cap=0 不限 |
| 11 | `burn_closed_loop_and_replays_rejected` | 销毁闭环 / 双花 / burn_id 幂等 |
| 12 | `burn_rejects_real_domain_notes` | REAL 域拒入 Burn（对称纪律） |
| 13 | `burn_rejects_token_mismatch_and_play_slot` | token 错配 / PLAY note 拒烧 |
| 14 | `real_domain_two_way_rejection_preserved` | DepositV2×GAME / WithdrawV2×GAME 拒 + 计数 |
| 15 | `free_mode_faucet_skeleton_limits` | Free 骨架：单次/终身限量、owner 隔离 |
| 16 | `supply_identity_outstanding_and_reconciliation` | INV-TE-7 三边核对 + client_view 交叉 |
| 17 | `reconciliation_json_export_shape` | 日终导出 JSON（§5 样例） |
| 18 | `wal_roundtrip_restores_registry_and_outstanding` | WAL 全链路：注册表/outstanding/幂等恢复 |
| 19 | `borsh_discriminants_frozen_and_op_shape` | 判别值 11/12/13 + 效果摘要形状 |
| 20 | `issuance_metrics_and_outstanding_gauge` | 指标族 + outstanding gauge |

单元（`src/game_token.rs`）：`genesis_digest_binds_all_fields`、
`spec_new_validates_structure_fail_closed`、`validate_rate_band_bounds`、
`paid_mint_floor_formula_exact`、`registry_register_is_frozen_and_append_only`、
`reconciliation_json_shape`。

全量回归：`cargo test -p poker-appchain --release` → **331 passed / 0
failed**（基线 306，只增不减；连续 5 次全绿验证无并发测试抖动）。
