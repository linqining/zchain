# ABI_ASSET_ID：TE-M1 资产模型（`AssetId`）协议规范

状态：**TE-M1 冻结**（判别值 / token 常量 / borsh 布局 / 映射即本文交付起冻结）。
本文是 v2 层资产身份的唯一事实源；`docs/ABI.md`（v1）与 `docs/ABI_V2.md`
不因本文修改。对应排期表 §6 TE-M1 行、plan-token-economy §1（方案 A：
趁 v2 alpha 未冻结一次改型，避免 v1→v2→v3 两轮迁移债）。

代码落点：`poker-appchain/src/asset_id.rs`（新）、`note_v2.rs`（改型）、
`sequencer.rs`（最小适配，逐行标注 `TE-M1`）、`client_view.rs`（v2 视图）。

---

## 1. 类型

### 1.1 `AssetDomain`（判别值冻结）

```text
REAL = 1   // 真金筹码域：外部储备 1:1，提现走 finality 门
GAME = 2   // 游戏筹码域：提现豁免 finality 门（软确认语义，§5.1 分层）
```

- borsh 编码 = 判别值单字节（`use_discriminant = true`，与 v1
  `AssetClass` 同纪律）：REAL → `0x01`，GAME → `0x02`；未定义数值
  反序列化拒绝（fail-closed）。
- 追加新域 = ABI 版本升级（域集合封闭）。
- **PLAY 不建独立域/类型**（与 plan §1.1 的三域写法差异如实声明）：
  PLAY 是 GAME 域 `token_id = 0` 的**遗留特例**——只以常量
  `GAME_TOKEN_PLAY = 0` 与文档固定，不新建枚举臂。

### 1.2 `AssetId`

```text
AssetId := { domain: AssetDomain, token_id: u32 }
```

- borsh 字段序冻结：`domain`（u8 判别值）→ `token_id`（u32 LE）。
  例：`REAL/NATIVE` → `[0x01, 00 00 00 00]`；`GAME/PLAY` →
  `[0x02, 00 00 00 00]`。
- **整体参与 v2 note 承诺**（INV-TE-1）：

```text
asset_commitment(asset_id) = poseidon_hash_many([
    domain_felt("zchain.asset.v2.id"),   // DOMAIN_ASSET_ID_COMMITMENT（冻结）
    felt(domain as u8),
    felt(token_id),
])
```

  该单 felt 整体替换 v2 note 承诺 preimage 中的旧 `felt(asset_class)`
  位（`note_v2::NoteV2::commitment`）。`token_id` 不进承诺 = 同域不同
  币种可互换 = 对账与桌绑定全盘失效——因此它是承诺层输入，不是展示
  字段。note 承诺域标签 `zchain.note.v2` 本身**不变**。

### 1.3 REAL 域 token 常量（封闭枚举，冻结；TE-M2 启用）

| 常量 | 值 | 说明 |
|---|---|---|
| `TOKEN_NATIVE` | 0 | 原生代币（= v1 `AssetClass::Real` 的映射目标） |
| `TOKEN_USDT` | 1 | USDT（TE-M2 启用；本版仅冻结数值） |
| `TOKEN_USDC` | 2 | USDC（TE-M2 启用；本版仅冻结数值） |

REAL 域是封闭枚举：新增币种 = ABI 版本升级（plan §1.1）。封闭性强制
点 = 构造器 `AssetId::real`（越界 `OutOfRange` 拒）；类型层不阻止
borsh 反序列化出"REAL 域 + 未注册 token"——该值只可能来自伪造载荷，
会在守恒/迁移比对中因与任何合法账本资产不等被拒（fail-closed：
不认识 ≠ 接受）。

### 1.4 GAME 域 token 注册表（结构占位）

GAME 域 `token_id` 由 GTS 注册表分配（发新游戏币不改 ABI）。本任务
**只留结构不实现发行**：`AssetDomain::is_registered_token` 是唯一扩展
点（当前 GAME 域只认遗留 `GAME_TOKEN_PLAY = 0`）；TE-M3 的
`IssueGameToken`/`BurnGameToken`（判别值追加）落地时必须经该谓词。

---

## 2. v1 映射与"v1 路径零变更"边界

| v1（`note.rs`，冻结） | v2（`asset_id.rs`） |
|---|---|
| `AssetClass::Real`（判别值 1） | `AssetId { domain: REAL, token_id: TOKEN_NATIVE(0) }` |
| `AssetClass::Play`（判别值 2） | `AssetId { domain: GAME, token_id: 0 }`（遗留特例） |

- **映射冻结且唯一**：`AssetId::of_v1` / `AssetId::to_v1_class`。
  非遗留资产（REAL/USDT、REAL/USDC、GAME 非零 token）在 v1 账本
  **无表示**（`to_v1_class = None`），调用方必须 fail-closed 处理。
- **v1 路径零变更**：v1 Note ABI、v1 结算（`settlement.rs` 的
  `AssetClass` 源定义属 poker-settlement-core/`note.rs` 冻结面）、v1
  托管 finality 门（`vault.rs` 判 `AssetClass::Real`）、v1 错误变体
  `AssetClassMismatch` 全部不动。既有 247+ 测试语义保持（v2 相关测试
  按新模型等价改造）。
- v1 资产进入 v2 校验只有一处换算：`SettleInputV2::V1` 的
  `asset_id()` 经 `of_v1` 升维；MigrateNote 的 `record.asset_class`
  （owner_v2 冻结字段，`migrate_digest` 覆盖不变）在 sequencer 准入
  经 `of_v1` 升维后与 minted 的 `asset_id` 全等比对。

---

## 3. TE-M1 变更记录（ABI_V2.md §1 的增量，本文代管）

ABI_V2.md 冻结不改正文，以下为其 §1 字段表与 §1.2 承诺式的
**TE-M1 增量**（NoteV2 尚未上链，无冻结包袱）：

| 项 | 变更前（ABI_V2.md §1.1/§1.2） | 变更后（TE-M1） |
|---|---|---|
| `NoteV2` 字段 0 | `asset_class: AssetClass`（u8 判别 Real=1/Play=2） | `asset_id: AssetId`（u8 域判别 + u32 token，§1.2 布局） |
| `NoteSpec2` 字段 0 | 同上 | 同上 |
| note 承诺 preimage 第 2 位 | `felt(asset_class as u8)` | `asset_commitment(asset_id)`（域 `zchain.asset.v2.id`） |
| 同类守恒 | 全部输入/赔付/rake 同 `AssetClass`（`AssetClassMismatch`） | 全部输入/赔付/rake 同 `AssetId`（domain 与 token_id 任一不同 → **`AssetMismatch`**，新错误变体） |
| `SettleInputV2` 资产访问器 | `asset_class() -> AssetClass` | `asset_id() -> AssetId`（V1 臂经 `of_v1` 升维） |
| `settle_effect_v2` 赔付段 | `owner_commitment ∥ amount` | `owner_commitment ∥ asset_commitment(asset_id) ∥ amount`（资产维度进签名覆盖） |
| v2 域标签 | `zchain.note.v2.*`（冻结） | **不变** |
| `MigrateNoteRecord` | `asset_class: AssetClass` + `migrate_digest` | **不变**（升维发生在 sequencer 准入比对） |
| `Operation` 判别值 | MigrateNote=7 / SettleV2=8 | **不变**（载荷内类型随上表变更） |

`NoteV2::assert_same_class` 更名为 `assert_same_asset`（语义 =
AssetId 全等）。

---

## 4. finality 语义决策（冻结）

提现/出证 finality 门按 **domain** 判，不按 token 判：

```text
gate_applies(asset_id) = asset_id.is_real_domain()
```

- REAL 域**任何** token（NATIVE/USDT/USDC）走 finality 门；
- GAME 域**任何** token（含遗留 PLAY）豁免（软确认即可提，§5.1 分层）；
- 判据与 v1 门（`vault.rs` 判 `provenance.asset_class == Real`）经冻结
  映射逐点重合：`is_real_domain(of_v1(c)) ≡ (c == Real)`——既有
  finality 测试零回退；
- **禁止**退化为逐 token 白名单（TE-M2 扩展托管分账时以本节为准）。

sequencer 侧 v2 余额分栏（`balances_v2_of`、`ClassPair` v2 侧）同款
domain 判据：REAL 域合计 / GAME 域合计；逐 `AssetId` 细分视图 =
`client_view::v2_balances_by_asset`。

---

## 5. 边界（如实声明 / 诚实降级点）

1. **GAME 发行未实现**（TE-M3）：无 GTS 注册表、无 IssueGameToken/
   BurnGameToken；GAME 域当前只有遗留 token 0 结构性存在。
2. **REAL 多币种通道未实现**（TE-M2）：`OpenTable.currency`、
   `Deposit` 载荷扩展、`CustodyLedger` 按币种分账、watcher 多通道打款
   均未动；本版 REAL 域 USDT/USDC 只冻结判别值与构造器封闭枚举。
3. **v2 结算的 rake 通道仍是 v1 账本**：rake 输出是 v1 `NoteSpec`
   （`asset_class`）。非遗留资产（REAL/USDT、REAL/USDC、GAME 非零）
   在 v1 无表示 → v2 结算若声明非遗留资产且 rake > 0，校验必然
   `AssetMismatch` 拒（fail-closed）。rake 多币化属 TE-M2/M3。
4. **提现路径是 v1 专属**：`WithdrawalProvenance`/`vault` 按冻结的
   `AssetClass` 工作；v2 note 的提现通道与 AssetId 粒度 finality 门
   接线属 TE-M2（判据已由 §4 冻结）。
5. **v2 承诺 AIR 覆盖边界不变**：资产身份进 host 侧校验关系与承诺
   preimage；canonical AIR 约束未扩展（承 ABI_V2.md §边界）。
6. plan-token-economy §1.1 示例把 REAL 域 code 记为 {1,2,3}、PLAY 记
   为独立域 class=2；**本文为冻结口径**（REAL=1/GAME=2，token 0 起），
   以"判别值与 v1 映射自洽（Real→token 0、Play→GAME token 0）"为
   取舍依据，差异在此如实声明。
