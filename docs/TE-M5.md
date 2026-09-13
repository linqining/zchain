# TE-M5 — UI/explorer 呈现规范（资产标识 / 分栏 / 对账页）

排期表 §6 TE-M5 行：**REAL 多币种与 GAME 币的资产标识/分栏/对账页**。
上游依赖：TE-M1（AssetId 资产模型）、TE-M2（REAL 三币种）、TE-M3（GTS
游戏币）、TE-M4（GAME 桌销毁计费）。

本文件是**呈现规范**：规定资产维度在 explorer 数据面、扩展 UI 与官网
explorer 页的展示口径、数据源映射与边界。展示层不做任何语义创新——一切
资产语义以 `poker-appchain/src/asset_id.rs`（冻结判别值）与 sequencer
只读访问器为唯一事实源。

---

## 1. 资产标识模型（展示层口径）

```text
AssetId := { domain: AssetDomain, token_id: u32 }   # ABI v2 冻结
REAL 域（domain=1）：0=NATIVE / 1=USDT / 2=USDC     # 封闭枚举，新增 = ABI 升级
GAME 域（domain=2）：0=PLAY(legacy 遗留特例)；token_id ≥ 1 = GTS 注册游戏币
```

- v1 `AssetClass` 经**冻结映射**升维：`Real → REAL/NATIVE(0)`、
  `Play → GAME/PLAY(0)`（`AssetId::of_v1`，唯一换算）。展示层对 v1 记录
  （v1 结算、v1 钱包 note）一律经该映射显示，不得发明第二种换算。
- **名称解析**：REAL 域用封闭枚举静态表；GAME 域 GTS 注册币**没有链上
  名称字段**（genesis 规格不含 name），展示用 `token <id>` 编号或网关注
  册表解析——刻意不静态登记链下名称，避免与链上注册表漂移。未知
  token_id 一律 fail-closed（不造名、不猜测）。
- 规范字符串：`real:native` / `real:usdt` / `real:usdc` /
  `game:play(legacy)` / `game:<token_id>`（与 `AssetId::to_string` 同源）。

## 2. explorer 数据面（explorer_gateway）

全部为 GET、只读、白名单路由的**追加字段**（不改既有字段语义，两数据面
纪律不破坏）：

### 2.1 `GET /api/v1/status` → `assets`（仅 replay 模式）

| 字段 | 含义 | 来源（只读访问器） |
|---|---|---|
| `assets.source` | 数据来源标注（恒含 "chain-visible face"） | 常量 |
| `assets.real.tokens[]` | REAL 域封闭枚举三 token | — |
| `…{domain,token_id,token,asset}` | 展示名/规范字符串 | `AssetId::to_string` 同源拼写 |
| `…issued` | 存续 v2 note 面额 + 已销毁毛额（十进制字符串） | `LedgerState::issued_v2_real_by_token` |
| `…burned` | 提现销毁毛额合计 | `LedgerState.burned_v2`（只读字段） |
| `…outstanding` | `issued − burned`（= 存续面额） | 计算值 |
| `assets.game.tokens[]` | GAME 域逐 token 供给对账 | `LedgerState::game_reconciliation` |
| `…{minted_total,burned_total,outstanding,live_note_sum}` | 恒等式四边量（字符串） | 同上 |
| `…consistent` | `outstanding == live_note_sum`（false = 账本 bug 信号，原样透出） | 同上 |
| `…{registered,mode,anchor,rate,max_supply}` | 注册表规格展示（遗留 PLAY 规格字段为 null） | `LedgerState.game_registry` |
| `assets.game.all_consistent` | 全部 token 恒等式成立位 | 同上 |

大数一律**十进制字符串**（u128/u64，与 `game_reconciliation_json` 同纪律，
避免 JSON 数值精度歧义）；集合确定序（REAL 封闭枚举序 / GAME token_id
升序）。

**index 模式：`assets` 恒 null。** token 聚合账（`game_minted` /
`burned_v2` 等）是 WAL 重放重建态，不入归档索引——如实呈现"不可得"，
不从 v1 计数伪造。消费方（扩展/官网）必须把 null 渲染为"未获取"，禁止
渲染为空注册表或 0。

**边界（如实声明）**：托管侧储备（`CustodyLedgerV2` 的 reserved/浮存/
提现队列）与 L1 打款面网关不可达——`assets` 只覆盖**链上可见面**，
`assets.source` 固定标注。REAL 域 per-token 托管对账
（`reserved ≡ issued` 恒等式）属 portal 后端/托管部署面，本轮不呈现。

### 2.2 `GET /api/v1/settlement/{binding}` → `asset_id`

inputs / payouts / rake.treasury_out / rake.operator_out 逐项追加：

```json
"asset_id": { "domain": 1, "domain_name": "REAL", "token_id": 0,
              "token": "native", "asset": "real:native" }
```

v1 记录经冻结映射（Real → real:native、Play → game:play(legacy)）；
v1 摘要列表端点（`/api/v1/settlements`）保持"owner 缩写 + amount"最小
投影不变。

**边界**：settlements 明细本轮以 v1 `Settle` 记录为准（replay/index 两
数据面逐字段一致纪律；index 模式的 Settle 行只有 v1 摘要）。GAME 桌
`SettleV2` 在 `/api/v1/frames` 以 kind 呈现，其资产维度由
`status.assets` 的 GAME 域供给对账闭合；SettleV2 明细端点（含逐 payout
asset_id）需 archive index 同步扩展 v2 摘要行后另交付。

## 3. 扩展呈现（Extension 0.4.0-alpha 追加）

### 3.1 单一名称表（网络配置级）

`extension/common/networks.js` 的 `ASSET_TABLE` 是 token 名称解析的
**唯一**静态表（domainNames / realTokens / gameTokens）。任何 UI 不得
内联第二张表。

### 3.2 分组与徽章（`extension/common/assets.js`，纯函数）

- `assetIdOfV1`：v1 asset_class 冻结映射（唯一换算的 JS 侧）。
- `assetBadge`：余额行 / note 列表 / 签名预览 / 结算 payout 共用的徽章
  入口。优先消费网关 `asset_id` 字段；旧载荷回落 v1 asset_class 映射；
  未知 REAL token / 坏形状 → `UnknownAsset`（fail-closed，原样展示原始
  值，不造名）。徽章配色沿用域色：REAL=`badge-real`、GAME=`badge-play`。
- `groupBalances`：0.4 钱包账本仍为 v1 二元——REAL 域三列中只有 NATIVE
  有值；**USDT/USDC 列渲染为"未接入"（null），禁止渲染为 0**（null =
  未接入，0 = 已接入但为零，两者语义不同）。
- `summarizeGatewayAssets`：网关 `status.assets` → GAME 域注册币行；
  形状不符 fail-closed（`BadShape`）；`consistent:false` 行必须带告警
  原样透出。

### 3.3 popup / portal

- popup 余额：REAL 域（NATIVE 列 + USDT/USDC 未接入占位 + 托管警示）与
  GAME 域（遗留 PLAY + 已注册 GTS 游戏币列表）物理分组；GAME 组内注册币
  列表异步取自网关，未配置/不可达/BadShape 一律如实标注"未获取"。
- GAME 注册币行展示的是**链上供给对账**（outstanding =
  Σminted − Σburned，字符串原样透传），**不是用户余额**（0.4 钱包无
  GAME v2 note）——UI 文案必须写明，禁止把供给数字渲染成余额。
- note 列表与签名预览：逐条资产徽章（域/币名）。
- portal 结算明细：payout 逐条徽章（网关 `asset_id` 优先，v1 映射回落）。

## 4. 官网 explorer 页（website/content/explorer.md）

新增"资产标识"小节，如实说明：AssetId 两级标识与封闭枚举；REAL 多币种
独立托管/独立提现/**禁跨币轧差**（协议强制）；GAME 币单向结构性质（不可
赎回/不可兑换/不可桥——操作集无出口变体，非运营策略）、供给恒等式
`outstanding = Σminted − Σburned` 三边核对、GAME 桌销毁计费（FixedRakeBurn
收缩 outstanding）。措辞纪律见 §6。

## 5. 对账页数据源映射（汇总）

| 呈现项 | 数据源 | 模式可用性 |
|---|---|---|
| REAL 三 token issued/burned/outstanding | `status.assets.real.tokens[]` | replay；index = null（如实标注） |
| GAME 逐 token 供给恒等式四边量 + consistent | `status.assets.game.tokens[]` | 同上 |
| GAME 注册表规格（mode/anchor/rate/max_supply） | `status.assets.game.tokens[]`（`game_registry` 投影） | 同上 |
| 结算 payout/input 资产徽章 | `settlement/{binding}` 的 `asset_id` | replay/index（v1 Settle） |
| REAL 托管储备/提现队列（reserved ≡ issued） | **不呈现**（网关不可达；部署面） | — |
| SettleV2（GAME 桌）明细 | **暂以 frames kind + status.assets 闭合**；明细端点后置 | — |

## 6. 措辞纪律（合规红线，对齐 TEC-v1）

- 禁用词全站 0 命中（`website/tools/scan_banned_words.py`：稳赚/零风险/
  绝对公平/银行级安全/guaranteed/proof of reserves 等）——因此**不得**
  出现"储备证明 / proof of reserves"类表述，REAL 托管只描述机制（独立
  分账/独立通道/禁轧差），不做储备充分性陈述。
- GAME 币表述定式：**游戏内虚拟筹码，非投资品**——不可赎回、不可与
  REAL 域资产兑换、不可跨链（结构性质）；无收益/回报/升值表述；供给数字
  只是对账记录，不构成价值陈述（参考 `docs/plan-token-economy-compliance-v1.md`
  §2 防御矩阵与闭环口径）。
- 数据诚实：null/未获取/未接入/不一致四态必须如实渲染，禁止把"没有数据"
  表达成"数据为零"。

## 7. 交付边界（如实声明）

- **UI 对账页属 portal 后端部署面**：本轮交付的是 explorer_gateway 数据
  面（status.assets + settlement asset_id）、扩展呈现（分组/徽章/注册币
  列表）与官网 explorer 页说明；生产对账页（托管储备、提现队列、L1 打款
  面）随 portal 后端部署单独交付。
- index 模式的资产摘要（需 archive index 携带 token 聚合投影）与
  SettleV2 明细端点为后置项，当前如实降级为 null / kind 展示。
- 扩展 0.4 钱包账本仍为 v1：REAL 域 USDT/USDC 列与 GAME v2 余额为展示
  占位（未接入），随 v2 账本接入（MigrateNote/DepositV2 客户端路径）启用。

## 8. 测试与验收

- 网关：`cargo test -p poker-appchain --release --test te_m5`（status
  assets 三域断言 / index null / settlement asset_id / 名称拼写钉住）；
  既有 `--test explorer_gateway` 零回退。
- 扩展：`extension/tests/assets.test.js`（12 用例：冻结枚举/映射/徽章/
  分组/形状校验/注入 fetch 错误路径）；`npm test` 全量零回退。
- 官网：`scan_banned_words.py` / `check_links.py` / `check_a11y.py` 三件
  套零命中。
