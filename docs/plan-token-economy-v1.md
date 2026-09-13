# ZChain 代币经济系统设计 v1（TE-v1）

| 项 | 值 |
|---|---|
| 状态 | 草案（设计冻结前评审稿） |
| 日期 | 2026-09-13 |
| 关联 | `docs/plan-appchain-v1.md`（§5.4、§6.1）、`docs/plan-token-economy-compliance-v1.md`（TEC-v1，合规框架）、`poker-appchain/docs/ABI.md`（v1.3）、`src/note.rs`、`src/ops.rs`、`src/fee.rs`、`src/vault.rs`、`src/real_policy.rs`、`src/settlement.rs` |
| 里程碑前缀 | TE-M1..TE-M5（沿 M 编号惯例，不与既有 M0..M9 冲突） |

---

## 0. 背景、目标与非目标

### 0.1 现状基线

- 链内无 gas，收入来自**可证明 rake**（plan §0、`fee.rs`）。
- 资产域是二元的：`AssetClass::{Real, Play}`（`note.rs`），隔离在承诺哈希与
  AIR 层强制——跨类互转**不可证明**，不是业务层断言。
- REAL note 面额单位 = 结算层原生代币 wei（"STRK wei"口径），**单一币种**。
- 托管账 `CustodyLedger`（`vault.rs`）只有总量级对账：
  `delta = reserved − issued`，REAL 提现过 finality 门（水位 + 批次根）。
- 操作集封闭（`ops.rs`），判别值只能**尾部追加**；ABI v2（NoteV2 /
  MigrateNote / SettleV2）处于 alpha，尚未主网冻结。
- plan §6.1 明文：v1 不发行"必须购买才能使用"的原生代币。本设计不改变
  该承诺（见 §10.1）。

### 0.2 本设计引入的四个变化

1. **REAL 现金桌多币种化**：原生代币、USDT、USDC 三种入金币种可在
   REAL 现金桌使用，各自独立托管、独立对账、独立提现通道。
2. **GAME 代币标准（Game Token Standard, GTS）付费模式**：新增游戏币
   资产域，发行时冻结"锚定资产 → 游戏币"铸造比率，比率必须落在协议
   许可价带内。
3. **结构性单向与封闭**：游戏币不能跨链桥、不能与原生代币或稳定币
   兑换——由封闭操作集 + AIR 不可证明共同保证，不是运营策略。
4. **FREE 模式（免购买 + gas 收费）**：GTS 的第二种发行模式——游戏币
   经 faucet 免费限量铸造（不销售），商业化改为按对局收取固定 gas
   服务费（以原生代币/稳定币计价）。这是"PLAY 的可收费版本"；PLAY
   免费层本身永久保留（TEC-v1 §2 的敌意辖区防御依赖它）。

### 0.3 非目标（明确不做）

- **链内不做任何币种兑换（FX）**：状态机不存在"换汇 op"。玩家要 USDT
  敞口就充 USDT。理由：任何兑换率都是协议外生参数，进状态机会破坏
  守恒不变量的可证明性（M2 的 `ConservationViolated` 校验依赖"同资产
  面额守恒"这一强形式）。
- **不做跨链桥**：REAL 域出入金维持既有 v1 托管通道（外部链收款 →
  watcher 确认 → 铸 note；提现走 `WithdrawRequest` + finality 门）。
  GAME 域连这条通道也不开（§3.4）。
- **不做游戏币赎回**：单向性是产品与合规定义（social-casino 模型），
  不是待补的技术功能。
- **不发新原生代币、不改"游戏操作免 gas"基线**：原生代币指结算层既有
  原生资产，不是新发行的准入券。

---

## 1. 资产域模型：`AssetClass` → `AssetId`

### 1.1 三域结构

把现有二元 `AssetClass` 推广为**资产域（class）+ 币种/代币（code）**两级：

```text
AssetId := (class: u8, code: u32)

REAL  域 (class=1)：code ∈ { 1=NATIVE（原生代币）, 2=USDT, 3=USDC }
GAME  域 (class=3)：code = token_id（GTS 注册表分配，见 §3.1）
PLAY  域 (class=2)：code=0 保留（既有休闲类，兼容期遗留）
```

判别值纪律：`Real=1 / Play=2` 沿用现值不动，`Game=3` 追加。REAL 域内
code 是**封闭枚举**（v1 只有三种，新增币种 = ABI 版本升级）；GAME 域内
code 是**注册表分配**（发新游戏币不改 ABI）。

### 1.2 承诺与隔离（INV-TE-1）

- `AssetId` 整体参与 note 承诺哈希（class 与 code 都进 Poseidon 输入，
  沿用 `Note::commitment` 的无损编码纪律）。**code 不进承诺 = 同类不同
  币种可互换 = 对账与桌绑定全盘失效**，因此这是 AIR 层输入，不是展示字段。
- 现有"REAL/PLAY 跨类互转 AIR 不可证明"（M1-ACC-2）推广为：
  **跨 `AssetId` 的 Transfer / BuyIn / Settle witness 不可证明**。
  `settlement.rs` 已有的同类校验（inputs / outputs / rake 逐一对
  `asset_class`）改为逐一对 `asset_id`，语义形状不变，粒度变细。
- nullifier 树分库纪律（note_store REAL/PLAY 物理分库）推广为
  REAL / GAME 两库；REAL 库内三币种共树（靠承诺内 code 区分），
  GAME 库按 token 分区（§3.7）。

### 1.3 ABI 落点（决策点 TE-D1）

| 方案 | 内容 | 代价 |
|---|---|---|
| A（推荐） | 趁 ABI v2 alpha 未冻结，把 `NoteV2.asset_class: AssetClass` 升级为 `asset_id: AssetId`；v1 note 经既有 `MigrateNote` 路径迁 v2 | v2 alpha 改型一次；主网冻结后零迁移债 |
| B | v2 照发，另开 NoteV3（asset_id），二段迁移 v1→v2→v3 | 判别值最干净，但两轮迁移、三套并存的验证臂 |

方案 A 的前提是 v2 alpha 尚无主网数据依赖；若冻结已发生则退 B。

---

## 2. REAL 多币种现金桌

### 2.1 桌币种绑定（INV-TE-6）

- `OpenTable` 增加 `currency: AssetId`（必须落在 REAL 域封闭枚举内），
  与 `FeePolicy` 一并在开桌时冻结——费率是状态机里的数据（plan §0），
  币种同理：**开桌后不可改**，改 = 关桌重开。
- `BuyIn`：被消费 note 的 `asset_id` 必须等于桌 `currency`，否则
  `AssetClassMismatch`（错误语义推广为 AssetMismatch）。
- `Settle`：一桌一手全程单币种（§2.4 守恒）。
- GAME 域 `AssetId` 出现在 `OpenTable.currency` → 拒绝（REAL 桌只收
  REAL 域；GAME 桌走 §3.5 的独立入口，不是同一字段的另一个取值——
  两类桌的费率策略、监管口径、finality 语义都不同，刻意不复用）。

### 2.2 托管账本按币种分账（INV-TE-2）

`CustodyLedger` 的每一条总量从标量变成按 REAL 币种的三份账：

```text
reserved[code]                // 外部储备（watcher 按币种读链上余额）
deposits[code]                // 入金确认记录（deposit_id 幂等，载荷含 code）
withdrawals[code]             // 提现队列（entry 含 code）
issued_real_total[code]       // sequencer 账本聚合，按 code 导出

对账恒等式（每币种独立，逐日）：
    delta[code] = reserved[code] − issued_real_total[code] == 0
浮存分解（沿 M7）：
    pending_withdrawal_total[code]
      == pending_payout_total[code] + pending_fee_float[code]
```

- 任一 `code` 的 `delta != 0` 即 `ReconciliationMismatch{code}`——
  **不允许跨币种轧差**（USDT 短库不能用 NATIVE 长库抵），这是托管
  破产隔离的账面表达。
- `WithdrawalFeeConfig` 按币种各配一份（flat fee 以该币种计价；外部
  gas 成本结构不同）。
- 提现 finality 门（§5.4：水位 + 批次根）语义不变，REAL 域三币种
  全部适用；PLAY/GAME 豁免口径不变。

### 2.3 出入金通道

- **入金**：外部链（v1：Starknet）按币种设收款地址/合约白名单：
  NATIVE = 原生转账；USDT/USDC = 白名单 ERC20 合约 `transfer`。
  watcher 按币种确认 → `Deposit` op（载荷含 `asset_id`）→ 铸
  REAL note。`deposit_id` 幂等语义不变。
- **打款执行器**：`queued_payouts()` 快照携带 code，按币种分通道
  执行（原生转账 / ERC20 transfer），`mark_paid` 语义不变。
- USDT/USDC 外部合约地址白名单是**运营参数 + 协议常量**双层：白名单
  变更走版本化治理，不进状态机。

### 2.4 rake 与守恒（INV-TE-5）

- rake 以桌币种 in-kind 计取，`FeePolicy::FixedRake{rate_bps, cap,
  split}` 结构不变——不同币种桌各自绑定各自策略（费率可以不同）。
- 守恒不变量按 `asset_id` 粒度重述：
  `Σinputs.amount == Σoutputs.amount + rake_total`，全部同
  `asset_id`；违例 `ConservationViolated`（现有错误形状）。
- **协议不定汇率**：UI 的法币折算显示用外部预言机，仅展示层，永不进
  状态机。

---

## 3. GAME 代币标准（GTS）

### 3.1 Token 注册表（Genesis 冻结）

每个游戏币是一个独立 token，由**发行记录（genesis）**定义，注册后
全部字段不可变（改价 = 发新 token，旧 token 自然消亡）：

```text
TokenGenesis {
    token_id:    u32            // 注册表分配
    issuer:      [u8; 33]       // 发行方公钥（v1 = 平台运营方）
    mode:        IssuanceMode   // 发行模式（Paid / Free，下）
    max_supply:  u64            // 0 = 不限
    genesis_commitment           // poseidon(DOMAIN_TOKEN_GENESIS, 上述全字段)
}

IssuanceMode :=
    Paid { anchor: AnchorAsset, rate: u64 }   // 付费铸造：锚定资产 + 比率（§3.2 价带）
    Free { faucet: FaucetPolicy }              // 免费铸造：faucet 限量 + 桌级强制 gas 收费（§3.8）
```

- Paid 模式 `rate` 定义：**R = 每 1 单位 anchor 资产可铸游戏币数量**。
  示例 `R = 1_000_000` 即 1U = 100 万游戏币。
- 锚定资产以 1e18 wei 计价参与换算：`mint = floor(pay_amount_e18 * R / 1e18)`，
  向下取整，铸造尘埃 < 1 币留在未铸侧（fail-closed，无分数币）。
- Free 模式无 anchor 无 rate；其成本覆盖与商业化约束在 §3.8（gas
  服务费），faucet 参数进 genesis 同样冻结。

### 3.2 发行价带（INV-TE-4，用户需求的核心约束）

`rate` 必须落在协议许可价带 `[R_min, R_max]`（治理参数，版本化）：

| 界 | 含义 | 保证 |
|---|---|---|
| `R ≥ R_min`（最低比率） | 单个游戏币的**名义锚定价值 ≤ 1/R_min** | 游戏币保持 play-money 属性：不可能被当作高价值筹码使用，避免游戏桌变相成为 REAL 现金桌、绕开现金域监管口径；同时给 u64 面额留余量（见下） |
| `R ≤ R_max`（最高比率） | 单个游戏币的**发行价 ≥ 1/R_max** | **运营成本覆盖**：每币摊销成本必须低于最低发行价，否则发行越多亏越多 |

**成本覆盖推导**（`R_max` 的取值依据，进治理文档每年复核）：

```text
设每币摊薄运营成本（以 anchor 资产计价）
    c = (结算 gas + 证明成本 + 基础设施 + 出入金通道费) / 预期流通币量
覆盖条件：发行价 1/R ≥ c   ⟺   R ≤ 1/c
取安全边际：R_max = 1/(k·c)，k ≥ 5（成本估计偏差 + 币量估计偏差）
```

**u64 余量核算**（`R_min` 的取值依据）：

```text
u64 最大 ≈ 1.8e19。
R_min = 1e5/U 时：1e10 U 等值经济规模 = 1e15 币，余量 ~1800x，充足。
R_min 不高于 1e6/U（即单币名义价值不低于 1e-6 U 的方向不加限制）。
```

参考默认（示例值，最终由治理评审定）：`R_min = 1e5`，`R_max = 1e7`
（围绕典型发行 `1U = 100 万` 上下各一个数量级）。

**强制点**（双层，与 REAL/PLAY 隔离同纪律）：

1. validation 层：`IssueGameToken` 提交时 `rate ∉ [R_min, R_max]` →
   拒绝，计 `issuance_rate_rejected_total`；
2. AIR 层：`rate` 进 `genesis_commitment`，价带参数进证明公共输入——
   带外 rate 的发行 witness 不可证明。

### 3.3 单向性：买入即终局（INV-TE-3）

游戏币的全部生命周期：

```text
        IssueGameToken（唯一入口，幂等）             BurnGameToken（唯一出口）
anchor ────────────────────────────► GAME 币流通 ──────────────────────► 销毁
(外部支付给协议金库，watcher 确认)      │  ▲
                                       │  └─ GAME 桌牌局消耗（rake → burn）
                                       └─ 玩家间 Transfer / 桌内循环（域内自由）
```

- **入口**：玩家在外部链把 anchor 资产付到协议金库地址 → watcher 按
  `issue_id` 幂等确认 → `IssueGameToken{issue_id, token_id, buyer,
  pay_amount}` 铸币。完全复用 `Deposit` 的托管确认模式；发行支付
  **全额进协议金库**，不退回、不分给发行方（v1；发行方激励见 TE-D3）。
- **没有反向 op**：封闭操作集（`ops.rs`）里不存在"GAME → anchor"的
  变体，且跨 `AssetId` witness AIR 不可证明（INV-TE-1）——
  **"不能和原生代币或稳定币兑换"是结构性质**：不上线该 op、不写该
  AIR 约束，任何人（包括运营方）都无法在协议内构造兑换。
- **提现拒绝**：`WithdrawRequest` 的 note 属 GAME 域 → 拒绝
  （fail-closed 负例），计 `game_withdraw_rejected_total`。
- **出口**：`BurnGameToken{spend, note}`——GAME 域 only，rake 回收与
  玩家主动销毁共用；供给恒等（INV-TE-7）：
  `outstanding(token) = Σ minted − Σ burned`，由账本聚合导出，
  explorer 按区块公布。

### 3.4 不可跨链（INV-TE-3 的外部面）

appchain 的全部外部资产通道只有两条：`Deposit`（入）与
`WithdrawRequest`（出）。GAME 域在这两个 op 上都是拒绝路径，因此：

- 现有架构下 GAME 币**没有**任何离开本链的状态转移路径；
- 未来若引入通用桥 / 第三方桥，桥的资产白名单默认排除 GAME 域
  （桥只能通过 op 集驱动，op 集已经拒绝——桥在协议外无权限）；
- settlement 到 L1 的批次根 / aggregate root 照常包含 GAME op 的
  承诺（审计需要），但**不含任何外部兑付语义**——L1 合约对 GAME
  域承诺只验证、不兑付。

### 3.5 GAME 桌

- `OpenTable` 的 GAME 入口：载荷为 GAME 域 `AssetId`
  （class=Game + token_id），桌内 BuyIn/Settle 全程单 token。
- 费率策略追加**尾部变体** `FeePolicy::FixedRakeBurn{rate_bps, cap}`
  （判别值顺延，additive 纪律）：rake 在结算时**直接销毁**（供给
  sink 前置，不需要 treasury 先收再 burn 的两跳）。也允许 `Zero`
  （纯娱乐桌）。`FixedRake`（分账）对 GAME 桌不适用——GAME rake
  分账会产生"游戏币收入"主体，混淆单向性叙事，v1 禁用。
- GAME 桌结算**不要求** REAL 证明链（沿 §5.1 分层：host-validate
  attestation 可用于 GAME；REAL 三币种维持 StarkRequired 三层门）。

### 3.6 与 PLAY 的关系

- PLAY 保留为 GAME 域的**遗留特例**：token_id=0、无 anchor、faucet
  铸造、不可购买。零监管敞口的测试/娱乐定位不变（plan §6.1）。
- 迁移路径（非本设计强制）：PLAY 流量逐步引导至 GTS 框架下的平台
  自营 token（有 anchor、有价带、有供给记账），PLAY 最终退役。
  退役前 PLAY 与 GAME 共享域内隔离规则（跨 token 不可转）。

### 3.7 存储与分区

- note_store：GAME 库按 `token_id` 分区（对齐 REAL/PLAY 物理分库
  纪律）——单 token 的 nullifier 集独立，爆炸半径隔离。
- token 注册表：append-only JSONL（沿 bond.rs 纪律：空文件合法、
  撕裂尾行忽略 + 告警、中间行损坏拒绝）。

### 3.8 FREE 模式：免购买 + gas 服务费（第三种商业化）

#### 3.8.1 模式语义

GTS 两种发行模式共享 GAME 域全部隔离不变量（不可桥、不可兑、不可跨
token 转移），商业化路径不同：

| | Paid 模式（§3.1-3.4） | Free 模式（本节） |
|---|---|---|
| 获币方式 | 外部支付 anchor 资产按比率铸造 | faucet 免费限量铸造 |
| 商业化 | 发行支付全额进金库 | 按对局收 gas 服务费 |
| 成本覆盖点 | 发行价带 `R ≤ R_max`（§3.2） | `fee_per_hand ≥ c_hand`（§3.8.4） |
| 币的稀缺性 | 买断（消耗即减） | 刻意不稀缺（faucet 持续供给） |

**币不稀缺是 Free 模式的合规要件而非缺陷**：判定"筹码是否为有价值
物"的核心是稀缺性与获取成本（*Kater* 判例的"延长游戏"理论，TEC-v1
§2）。faucet 持续免费供给 + 无任何兑付出口 = 赢得再多币也无边际价值
→ 赌博三要件缺"奖品"。**因此 faucet 不得人为稀缺化**——供给收紧到
"付费才能继续玩"的程度 = 退化为 Paid 模式的监管画像（WA 判例正是这么
认定的）。faucet 参数进 genesis 冻结，变更视为合规敏感变更（法务
复核清单，TEC-v1 §2.1）。

#### 3.8.2 GasPolicy（桌级冻结）

```text
GasPolicy {
    currency:     AssetId        // REAL 域三币种之一（服务费计价）
    fee_per_hand: u64            // 每手固定服务费（1e18 计价）
    split:        FeeSplit       // treasury / operator 分账（复用）
}
```

- **固定费额，刻意不与底池挂钩**：底池比例费 = 对筹码"抽水"，形似
  wager 上的 rake，损害"服务费"定性（TEC-v1 §2.1 三要件分析）；固定
  费 = 与胜负无关的服务定价（街机/订阅模型的按次收费形态）。
- 绑定 op：`BindGasPolicy{table_id, policy}`（判别值 13，additive），
  只能在 `OpenTable` 之后、**首次 `BuyIn` 之前**执行，绑定即冻结
  （与 FeePolicy 的开桌冻结同纪律）。
- **排序不变量（INV-TE-9，fail-closed）**：Free 模式 token 的桌未
  绑定 GasPolicy 前，首次 `BuyIn` 拒绝（计
  `gas_policy_missing_rejected_total`）。Paid 模式桌默认禁止绑定 gas
  （双重收费，放开 = 治理项 TE-D7）。
- PLAY 桌**永不**绑定 gas——永久免费层是合规防御（TEC-v1 §2），不
  商业化。

#### 3.8.3 gas credit（预付服务额度）

- **购买**：`BuyGasCredits{issue_id, payer, currency, amount}`（判别值
  12）。外部支付给金库（watcher 幂等确认，复用 `deposit_id` 模式），
  **不铸任何 note**——已售服务额度，不是链上负债：
  - 无赎回：额度只可被对局消耗，封闭操作集无退回变体；
  - 无储备义务：不进 `CustodyLedger` 对账恒等式（它是收入，不是
    reserved/issued 的一边）；
  - 计量账（sequencer 侧权威）：`credit(payer, currency) =
    Σpurchased − Σconsumed`，**INV-TE-8：逐玩家逐币种 ≥ 0**，消耗
    只发生在结算准入，逐笔导出进审计流。
- **消耗（准入控制，与 KYC/GEO 门同层）**：绑定 GasPolicy 的桌，
  每手 `Settle`/`SettleV2` 受理前校验每个参战玩家
  `credit ≥ fee_per_hand`，不足拒绝（计 `gas_credit_insufficient_total`
  ）；受理即按 `FeeSplit` 分账计提消耗。
- **结算守恒不动、AIR 零改动**：gas 是准入控制 + 计量，不进结算
  记录、不进 pot 数学——结算仍单资产（Free 币）守恒（INV-TE-5）。
  gas 可审计性由软确认帧内 op 流 + 计量账导出保证（运营审计层，
  与 KYC/GEO 同级），不上升为证明义务。
- **faucet**：`FaucetMint{token_id, owner, amount}`（判别值 11）。
  FaucetPolicy（进 genesis，冻结）：每玩家单位时间上限 + 单次上限；
  超限拒绝（计 `faucet_rate_limited_total`）。KYC 身份为限流键——
  币虽无价值，女巫刷币仍消耗结算资源。

#### 3.8.4 成本覆盖（Free 模式的价带等价物）

```text
每手摊薄运营成本（以 GasPolicy.currency 计价）
    c_hand = (结算 gas + 证明成本 + 基础设施) / 预期手数
覆盖条件：fee_per_hand ≥ c_hand
取边际：fee_per_hand ≥ k·c_hand，k ≥ 3
```

与 Paid 模式 §3.2 推导同源，但**直接以对局为单位**——Free 模式的收入
粒度与成本粒度天然对齐（每手），无需经币量间接摊销。定价披露：购买页
明示每手费用与计价币种（消费者定价透明，TEC-v1 §2.1）。

---

## 4. 经济流：收入、成本与对账

### 4.1 收入侧（全部可审计）

| 流 | 形式 | 记账 |
|---|---|---|
| REAL 桌 rake | in-kind，按桌币种（NATIVE/USDT/USDC） | `FeeSplit` treasury/operator 分账；rake_audit 既有导出按币种分列 |
| GAME 发行支付 | anchor 资产全额进协议金库 | `issue_id` 幂等账 + watcher 外部流水；金库余额进 `reserved` 口径外的运营账（不铸 note，单向性） |
| GAME 桌 rake | GAME 币计价 → 直接销毁 | 不是现金收入；作用是供给紧缩 + 再发行的持续需求 |
| Free 模式 gas 服务费 | 真实价值资产计价、每手固定费 | gas credit 计量账 + `FeeSplit` 分账；收入属性（无储备义务，§3.8.3） |

### 4.2 成本侧

- L1 结算 gas（原生代币计价）、证明成本（texas-air / proving_service）、
  基础设施、出入金通道费（外部链 gas + 稳定币合规通道）。
- **原生代币的三重角色**：REAL_NATIVE 现金桌币种之一；协议对外结算
  费用的支付资产；（v1.5+）validator bond 计价单位（`bond.rs` 记账
  框架已就位，量纲对齐即可）。

### 4.3 对账矩阵（日终）

```text
REAL 域（每币种独立，禁止轧差）：
    delta[NATIVE] = reserved[NATIVE] − issued[NATIVE]        == 0
    delta[USDT]   = reserved[USDT]   − issued[USDT]          == 0
    delta[USDC]   = reserved[USDC]   − issued[USDC]          == 0
    浮存分解（每币种）：pending == payout + fee_float

GAME 域（供给恒等，每 token）：
    outstanding(t) = Σminted(t) − Σburned(t) == Σ存续 GAME note 面额(t)

运营账（协议外，人工/半自动对账）：
    金库 anchor 收入 − 运营成本 ≥ 0 （TE-M5 起出月报）
```

---

## 5. 协议层强制点汇总

| # | 约束 | validation 层 | AIR / 结构层 |
|---|---|---|---|
| 1 | 跨 AssetId 不可转/不可混 | `AssetMismatch` 拒绝 | 承诺含 asset_id，跨域 witness 不可证明 |
| 2 | REAL 三币种独立对账 | `ReconciliationMismatch{code}` | 守恒按 asset_id；状态机无 FX op |
| 3 | GAME 不能兑回 anchor | `WithdrawRequest`(GAME) 拒绝 | 封闭 op 集无该变体；AIR 无该约束 |
| 4 | GAME 不能跨链 | 同上（出入金通道双拒） | 桥只能经 op 集驱动，无权限 |
| 5 | 发行价带 | `rate ∉ [R_min,R_max]` 拒绝 | rate 进 genesis 承诺 + 公共输入 |
| 6 | 桌币种绑定 | BuyIn/Settle 校验 | policy_commitment 含 currency |
| 7 | REAL 提现 finality 门 | 既有 §5.4 门不变（三币种同适用） | 既有水位 + 批次根语义 |
| 8 | GAME rake 即销毁 | `FixedRakeBurn` 结算校验 | 供给恒等进日终对账 |
| 9 | Free 桌先绑 gas 策略 | 未绑定即首次 `BuyIn` 拒绝 | GasPolicy 进桌策略承诺（冻结，INV-TE-9） |
| 10 | gas credit 非负 | 消耗前置校验拒绝 | 计量账恒等导出（审计层，INV-TE-8） |

所有拒绝路径 fail-closed、计 metric（§6）——与既有
`withdrawal_finality_rejected_total` 同惯例。

## 6. 指标增量（M9 惯例）

```text
REAL 域（label: currency=native|usdt|usdc）
  deposits_confirmed_total{currency}
  withdrawal_*（既有族 ×currency 标签）
  reconciliation_delta{currency}          // gauge，非零告警
  custody_exposure{currency}              // reserved，风险面板

GAME 域（label: token）
  game_token_minted_total{token}
  game_token_burned_total{token}
  game_token_outstanding{token}           // gauge
  issuance_rate_rejected_total
  game_withdraw_rejected_total            // 应恒 0 以外的出现即 bug 信号

Free 模式（label: currency, token）
  gas_credits_purchased_total{currency}
  gas_credits_consumed_total{currency}
  gas_credit_balance{currency}            // gauge
  gas_policy_missing_rejected_total
  gas_credit_insufficient_total
  faucet_mint_total{token}
  faucet_rate_limited_total
```

---

## 7. 合规与风险边界

1. **REAL 三币种 = 真金博弈**：沿既有 REAL 管控（白名单、限额、地理
   围栏、人工审核），USDT/USDC 增加储备破产隔离与稳定币脱锚监测
   （`custody_exposure` 单币种上限为治理参数）。
2. **GAME 币 = social-casino 模型**：不可赎回、不可桥、不可兑换 +
   名义锚定价值上限（R_min）四件套构成"非赌博筹码"的产品定义。
   但注意：(a) 付费购买不可赎回游戏币在部分辖区仍受社交博彩/消费者
   保护专门监管；(b) 不得以任何"面值/储备背书"话术宣传——锚定比率
   是铸造记账，不是价值担保，UI 必须明示"购买后不可退换、不可兑换、
   无任何价值承诺"（对齐 plan §6.9 禁用词纪律）。
3. **场外交易风险**：协议无法阻止链下场外兑付，但 R_min 保证单币
   名义价值极低 + 官方渠道零兑付，使场外市场缺乏定价锚。
4. **运营方作恶面**：v1 发行方 = 平台（TE-D3），金库 anchor 收入
   集中；对冲手段是 §4.3 运营账月报 + 供给恒等公开可审计。
5. **价带参数风险**：`R_min/R_max` 过紧会拒掉合理发行（有 metric 可
   见），过松失去意义——按 §3.2 推导式年度复核，参数变更走版本化
   治理并记录于 changelog。

---

## 8. 分阶段落地

| 阶段 | 内容 | 验收锚 |
|---|---|---|
| TE-M1 | `AssetId` 模型：类型 + 承诺 + 迁移（并入 v2 alpha 或 NoteV3，TE-D1）；`settlement.rs` 校验推广到 asset_id 粒度 | 跨 asset_id witness AIR 不可证明的负例测试（沿 M1-ACC-2 形状） |
| TE-M2 | REAL 多币种：`OpenTable.currency`、`Deposit` 载荷扩展、`CustodyLedger` 按币种分账、watcher/打款执行器多通道、finality 门三币种回归 | 三币种独立对账 + 跨币种轧差负例；finality 门既有测试 ×3 |
| TE-M3 | GTS：token 注册表、`IssueGameToken` / `BurnGameToken`（判别值 9/10 追加）、价带校验 | 价带外发行拒绝 + 不可证明负例；`WithdrawRequest`(GAME) 拒绝；供给恒等测试 |
| TE-M4 | GAME 桌：GAME 域开桌入口、`FixedRakeBurn`（判别值追加）、GAME 分区存储 | GAME 桌一手全流程 + rake 即销毁守恒测试 |
| TE-M5 | 面向外：explorer 币种/供给视图、UI（REAL 多币种风险标识、GAME 购买页单向性声明）、运营账月报 | plan §6 系的 ACC 项（明示资产类型/托管状态/不可兑换） |
| TE-M6 | Free 模式：`IssuanceMode::Free` + faucet + `GasPolicy` + gas credit 计量账（判别值 11/12/13 追加） | faucet 限流负例；未绑 gas 策略的首次 BuyIn 拒绝；credit 不足拒绝；credit 非负恒等；结算 AIR 零改动回归 |

依赖顺序：TE-M1 → TE-M2 → TE-M3 → TE-M4 → TE-M5；TE-M2 与 TE-M3
可在 TE-M1 后并行；TE-M6 依赖 TE-M3（GTS 框架），与 TE-M4/TE-M5
并行。

## 9. 决策点（评审时定）

| # | 决策 | 推荐 | 备注 |
|---|---|---|---|
| TE-D1 | AssetId 并入 v2 alpha（方案 A）还是新开 NoteV3（方案 B） | A | 前提：v2 alpha 无主网数据依赖；已冻结则 B |
| TE-D2 | `rate` 每 token 永久冻结 vs 治理可调 | 永久冻结 | 重定价 = 新 token；可调 rate 破坏审计简单性与用户预期 |
| TE-D3 | GAME 发行权限：v1 平台自营 vs 白名单第三方 | v1 平台自营 | 标准按第三方可扩展设计（issuer 字段已预留），白名单是 v2 治理项；发行方激励分成若引入，从金库运营账走，不动单向性 |
| TE-D4 | anchor 资产范围：三币种全开 vs 仅稳定币 | 仅稳定币起步 | NATIVE 作 anchor 会把原生代币价格波动传导进游戏币定价叙事；USDT/USDC 先行，观察后再扩 |
| TE-D6 | gas 服务费计价币种：稳定币 only vs 三币种 | 三币种允许、UI 默认稳定币计价 | 固定费额对计价币种价格波动敏感，稳定币最稳；已有 REAL_NATIVE 余额的用户有原生代币支付刚需 |
| TE-D7 | Paid 模式桌是否允许叠加 gas 收费 | v1 禁止 | 双重收费损害定价透明叙事；放开需治理评审 + 消费者定价披露重做 |

## 10. 与既有计划的一致性

### 10.1 "不发行原生代币"承诺（plan §6.1）

本设计**不违反**：原生代币是结算层既有资产（现金桌币种 + 协议费用
计价），不是新发行、不是准入必需——游戏操作依旧免 gas，PLAY 依旧
零门槛。GAME 币是娱乐消费品（单向购买、无赎回），不是"必须购买才能
使用"的功能券：不买 GAME 币也能玩 PLAY 桌。

### 10.2 资产隔离叙事升级

文档口径从"REAL/PLAY 两类"升级为"三域"：REAL（现金，多币种托管）/
GAME（游戏币，单向封闭，Paid/Free 双模式，Free 见 §3.8）/ PLAY（遗留
娱乐，永久免费层）。plan §6 系的全部 ACC
（页面显示资产类型、托管状态、风险提示）按三域重述；website 的
PLAY/REAL 徽章体系扩展 GAME 徽章（购买页强制单向性声明）。

### 10.3 BLOCKERS 增量

- B-TE-1：USDT/USDC 外部合约白名单的变更流程（治理签名 + 版本化）
  未定，TE-M2 前关闭。
- B-TE-2：`R_min/R_max` 初值的经济复核（真实 gas/证明成本数据）未
  做，TE-M3 前关闭。
- B-TE-3：GAME 币购买的支付通道（外部链收款地址复用 vs 独立）与
  KYC 界面未定，TE-M3 前关闭。
