# ABI v2 正式版协议规范（poker-appchain）

状态：**冻结候选**（v2 正式版接入；排期表 §1"ABI v2 正式版"行交付物）。
本文是 v2 协议的唯一事实源；`docs/ABI.md`（v1）不因本文修改——版本合并
由主控统一执行。v1 Note ABI（`note.rs`）与 v1 Operation 判别值 0..=6
**冻结不动**；v2 全部走 `note_v2.rs` / `ops.rs` 追加变体。

---

## 1. v2 Note（`note_v2::NoteV2`）

### 1.1 字段与 borsh 编码

borsh 字段序（`BorshSerialize`/`BorshDeserialize` 逐字段定长）：

| 序 | 字段 | 类型 | 说明 |
|---|------|------|------|
| 0 | `asset_class` | `AssetClass`（u8 判别：Real=1 / Play=2，沿用 v1） | 资产类 |
| 1 | `amount` | `u64` | 面额（STRK wei），> 0 |
| 2 | `owner` | `OwnerRef` | scheme(u8) + account_id(32B) + key_version(u32) + binding_id(Option<32B>) |
| 3 | `nonce` | `u64` | 铸币方单调序号（v1 为 32B 字节；v2 收窄为 u64） |
| 4 | `table_id` | `Option<u64>` | seat note 桌绑定 |
| 5 | `pot_index` | `u8` | 结算投影：pot 分层索引 |
| 6 | `runout_index` | `u8` | 结算投影：runout 索引 |

`OwnerRef` / `SignatureEnvelope` / `MigrateNoteRecord` / `VerifierMaterial`
的 borsh 形状沿用 `owner_v2.rs`（v2 alpha 已冻结）；v2 正式版为
`VerifierMaterial` **追加** borsh derives（`SettleInputV2::V2` 携带材料
进帧，WAL 重放全量复核）。

### 1.2 承诺（域标签冻结）

```
NoteV2.commitment = poseidon_hash_many([
    domain_felt("zchain.note.v2"),        // DOMAIN_NOTE_V2_COMMITMENT
    felt(asset_class as u8),
    felt(amount),
    hi(owner_commitment(owner)), lo(...), // owner_v2::owner_commitment（含 scheme/key_version/binding_id）
    felt(nonce),
    felt(table_id),                       // None → 0；Some(id) → id+1（与 v1 同编码）
    felt(pot_index),
    felt(runout_index),
])
```

- 域常量定义在 `note_v2.rs` 内（`zchain.note.v2` 命名空间）并**由本文
  冻结**；与 `felt.rs` v1 常量表（`poker-appchain.note.commitment.v1` 等）
  的关系：**独立命名空间，互不影响**——felt.rs 冻结，v2 常量不进该表，
  合并由主控决定是否在 ABI.md 附录收录对照表。
- `owner_commitment` 已含 scheme/key_version/binding_id：同一底层公钥在
  不同 scheme/version 下承诺必不同（v2 alpha 边界承诺的兑现）。

### 1.3 nullifier（防跨网/跨版重放）

```
NoteV2.nullifier(secret, spend_scope) = felt_to_bytes32(poseidon_hash_many([
    domain_felt("zchain.note.v2.nullifier.v1"),   // DOMAIN_NOTE_V2_NULLIFIER
    hi(commitment_bytes), lo(...),
    hi(owner_commitment(owner)), lo(...),         // scheme 参与派生
    hi(secret), lo(...),
    hi(blake2s32(spend_scope)), lo(...),
]))
```

`spend_scope` **必须**经 `note_v2::spend_scope(network_id, abi_version, tag)`
构造：`network_id(32B) || abi_version(u32 BE) || tag`。同一张 note 在不同
网络/ABI 版本下 nullifier 不同——跨网重放在 nullifier 层天然失效。

### 1.4 输出规格（`note_v2::NoteSpec2`）

字段与 `NoteV2` 相同（去 `nonce`，铸造时补齐）；`NoteSpec2::mint(nonce: u64)`
构造校验与 `NoteV2::new` 一致（amount > 0 + `validate_owner_ref`）。

### 1.5 迁移消费 nullifier（链侧派生）

```
migration_nullifier(record) = felt_to_bytes32(poseidon_hash_many([
    domain_felt("zchain.note.v2.migrate_nullifier.v1"), // DOMAIN_NOTE_V2_MIGRATION_NULLIFIER
    hi(record.old_commitment), lo(...),
    hi(record.migration_nonce), lo(...),
]))
```

迁移**不要求**旧 owner 交出 v1 spend secret：`migration_nonce` 被
`migrate_digest` 签名覆盖，链侧确定性派生的 nullifier 是旧 owner 授权的
确定性函数。派生域与 v1 nullifier 域分离——共享 `NullifierSet` 无跨版
碰撞。

---

## 2. Operation 追加变体（borsh 判别值）

additive 纪律：新变体只能追加在 enum 末尾（判别值 = 声明序，旧字节流
解码兼容）。

| 判别值 | 变体 | 载荷 | 状态 |
|---|---|---|---|
| 0..=6 | v1（OpenTable / CloseTable / Deposit / WithdrawRequest / Transfer / BuyIn / Settle） | — | 冻结 |
| **7** | `MigrateNote(Box<MigrateNoteOp>)` | `MigrateNoteOp { record: MigrateNoteRecord, minted: NoteV2 }` | v2 新增 |
| **8** | `SettleV2(Box<SettlementRecordV2>)` | 混合结算记录（§4） | v2 新增 |

- `Box` 仅 Rust 侧布局优化（`SoftConfirmFrame` 按值嵌入 Operation），
  borsh 编码与裸结构完全一致（v1 `Settle(Box<SettlementRecord>)` 同款）。
- `MigrateNoteOp` 载荷**刻意不含** `VerifierMaterial`（呈递材料）：
  材料是准入时证据，经 `Sequencer::submit_migrate(op, &material, now_ms)`
  呈递并全量验签（`validate_migrate_note` 8 步）。`Sequencer::submit`
  通道收到 `MigrateNote` 一律拒绝（fail-closed）。
- `effect_digest`：`MigrateNote → blake2s("effect.migrate_note.v2" ||
  borsh(record) || borsh(minted))`（无 SpendAuth，不被签名消费，确定性
  可审计）；`SettleV2 → blake2s("effect.settle_v2.v1" || settle_effect_v2)`。

---

## 3. MigrateNote 准入与应用（sequencer）

### 3.1 准入清单（`Sequencer::apply_migrate`，顺序即实现，全 fail-closed）

1. `record.network_id == config.network_id`（`SequencerConfig.network_id`，
   默认 `blake2s32("zchain-poker-devnet")`；生产网络必须显式覆盖）；
2. `record.abi_version == 2`（`OWNER_V2_ABI_VERSION`）；
3. `minted` 与 `record` 一致：amount / asset_class / owner(== new_owner_ref)；
4. `minted` 必须是自由余额形态：`table_id == None && pot_index == 0 &&
   runout_index == 0`——桌/投影绑定**不在** `migrate_digest` 签名覆盖内，
   fail-closed 拒绝未签名语义；
5. 旧 v1 note 存在（`LedgerState.notes` 键 = `old_commitment`）；
6. `migration_nonce` 全局查重（`LedgerState.migration_nonces: HashSet<32B>`，
   跨 note/跨 owner 一并阻断；命中 → `SettlementReplay`）；
7. 新承诺查重（`notes_v2`）；
8. owner_v2 校验：材料在场 → `validate_migrate_note` 全 8 步；无材料
   （WAL 重放侧，见 §6 边界）→ `validate_migrate_note_structure`
   （第 1–7 步：结构/摘要/新鲜度）。新鲜度 `now` = 帧 `ts_ms / 1000`
   （提交与重放同值，重放确定性成立）。per-signer 信封 nonce 水位
   （`LedgerState.owner_nonces_v2`，按 `owner_commitment` 索引）严格单调。

### 3.2 应用（变更段）

消费旧 v1 note（nullifier = `migration_nullifier`，入共享 nullifier 集）→
登记 `migration_nonce` → 推进旧 signer 的 v2 nonce 水位 → 铸 `NoteV2`
入 **v2 note 账本**（`LedgerState.notes_v2: BTreeMap<32B, NoteV2Entry>` +
`owner_index_v2`（键 = `owner_commitment`，不入状态根的纯性能索引））。

### 3.3 REAL/PLAY 与纪律

迁移保持同 `asset_class`（record ↔ minted 一致性强制）——REAL/PLAY
隔离不变。限流按既有 `ops_per_min` 令牌桶（principal = 旧 signer
`account_id`）。

---

## 4. 双 verifier 并行结算（`Operation::SettleV2`）

### 4.1 记录形状（`note_v2::SettlementRecordV2`）

`table_id, hand_binding, policy_commitment, pot, inputs, payouts, rake`。
与 v1 `SettlementRecord` 的**刻意差异**（如实声明）：

- **无 `SettlementPlan`**：v2 以单层 contested 口径计费
  （`rake.total == policy.rake_of(pot)`，`pot == Σinputs`，与
  `flat_settlement_plan` 语义一致）；plan 级 payout↔seat 投影绑定待
  v2 BuyIn/seat 生命周期引入后扩展；
- `inputs: Vec<SettleInputV2>`，判别式即 verifier 分派点：
  - `V1 { note: Note, spend: SpendAuth }`：既有 v1 路径——
    `spend_digest(commitment, nullifier, settle_spend_scope(hand_binding), effect)`
    + `verify_ecsdsa`；**seat 绑定纪律不变**（`table_id == Some(table_id)`）；
  - `V2 { note: NoteV2, nullifier, envelope: SignatureEnvelope, material }`：
    v2 路径——`settle_spend_verifier_v2`（scope =
    `settle_scope_v2(network_id, abi_version, hand_binding)` =
    `"zchain.owner_v2.settle.v1" || network_id || abi_version(BE) ||
    hand_binding`）。v2 输入桌绑定 ∈ {None, Some(table_id)}（v2 seat
    生命周期本版未引入，自由余额可参与结算——如实放宽，仅此一处）；
- `payouts: Vec<NoteSpec2>`（收款人 = OwnerRef，**铸入 v2 账本**）；
  `rake: RakeSplitRecord`（v1 类型，treasury/operator 是 legacy 33B 身份，
  **铸入 v1 账本**）。

### 4.2 逐输入签名（双 verifier 分派）

两条路径消费**同一**效果摘要 `settle_effect_v2`（域
`"zchain.owner_v2.settle.effect.v1"`，覆盖 hand_binding、pot、全部输入
承诺、全部输出 (owner_commitment, amount)、rake.total——分配结构篡改
对两种输入都必然签名失败）：

- **v1 verifier**：`spend_digest`（v1 域 scope）+ `verify_ecsdsa`；
- **v2 verifier**：`settle_spend_verifier_v2`——
  ① nullifier 非零；② `validate_envelope`；③ 信封签名者 == note owner；
  ④ `typed_data_digest == v2_spend_digest(...)`（v1 域签名在此必然摘要
  不一致 → 拒，**交叉伪造防线**；v1 臂进入 v2 验证器在分派层即拒）；
  ⑤ 新鲜度（expiry + per-signer nonce 单调）；⑥ `verify_owner_signature`
  按 scheme 分派（材料变体不匹配 → MaterialMismatch）。

### 4.3 其余 v1 纪律对齐

单类隔离（输入/赔付/rake 输出同类）、非零面额、守恒
（Σinputs == Σpayouts + rake 输出）、费率与 `policy_commitment` 绑定、
分账数额与收款人核对、`hand_binding` 非零 + 与 v1 **共享**
`settled_bindings` 集（跨版本重放一并阻断）、账本存在性核对（v1 输入
查 `notes`、v2 输入查 `notes_v2`，内容逐字段一致）。

### 4.4 v2 账本原语

`mint_note_v2`（承诺查重 + `created_at_op` + owner 索引）、
`consume_note_v2`（账本移除 + 索引同步 + 共享 nullifier 集消费）。
v2 note **不进 v1 承诺树**；状态承诺走状态根 v2 折叠段（§5）。

---

## 5. 状态根折叠与水位覆盖语义

### 5.1 状态根（`LedgerState::root`）

v1 折叠段（树根 → nullifier 根 → 注册表根 → 桌 → seq/spent_count）之后
追加 **v2 账本段**（顺序冻结）：

1. `notes_v2`（BTreeMap 承诺序）：`poseidon(acc, hi(c), lo(c),
   felt(created_at_op))` 逐条；
2. `migration_nonces`（HashSet **排序后**折叠——消除迭代序不确定性）；
3. `owner_nonces_v2`（BTreeMap 序）：`poseidon(acc, hi(k), lo(k),
   felt(nonce))`。

v2 账本与 nonce 集是**承诺状态**：WAL 重放必须逐位重现
（`tests/note_v2.rs::replay_restores_v2_ledger_and_nonce_sets` 钉住）。

### 5.2 迁移的水位/批次覆盖语义（**冻结**）

- migrate 走 sequencer op 流，`op_index` 单调；证明水位推进
  （`mark_proven_through(_with_root)`）**覆盖其 op_index**——迁移产出的
  NoteV2 随水位翻 `Proven`，finality 语义与 v1 产出 note 完全一致；
- **批次根仍只折叠结算绑定**：`pipeline::batch_root` 按结算绑定
  （v1 `settlement_binding`）折叠；**migrate 绑定与 SettleV2 不折入批次
  根**——它们的最终性由水位/批次范围覆盖表达（批次根 evidence 中的
  `through_op` 隐式覆盖区间内的 migrate/settle-v2 op）。采用该语义的
  原因：批次根折叠规则在 `pipeline.rs`（v1 冻结面），扩展折叠输入属
  协议升级而非 v2 接入必须；水位覆盖已给出等价的 finality 判定。
  **若未来要求批次根显式绑定 migrate**，需升级 `DOMAIN_BATCH_ROOT`
  折叠规则并升 ABI 次版本。

---

## 6. v1 共存与迁移纪律

- v1 Note ABI / v1 Operation（判别值 0..=6）/ `settlement.rs` /
  `fee.rs` / `pipeline.rs` / `wal.rs` / `soft_confirm.rs` / `felt.rs`
  零变更；v1 流程的 wire format 与签名语义不变；
- v1 与 v2 账本物理分离（`notes` / `notes_v2`），nullifier 集**共享**
  （派生域分离，跨版碰撞不可能，重放防线统一）；
- 迁移是 v1 → v2 的**单向桥**：同额、同类、消费旧 note、铸造新 note，
  不产生/销毁价值；`migration_nonce` 全局一次性；
- REAL/PLAY 隔离、限流、软确认链/WAL 纪律（P0-4 原子提交、先 WAL 后
  内存）对全部新路径不变；
- 客户端视图（`client_view::account_view`）：v1/v2 **分账本**聚合
  （v1 账户 = 33B 压缩公钥；v2 账户 = `OwnerRef`），REAL/PLAY 各自
  独立，不跨账本合并——账本版本与资产类同为隔离边界。

---

## 7. 边界（如实声明）

1. **canonical AIR 未纳入 v2 owner**：v2 输入的验签/nullifier/承诺规则
   是 **host 侧校验关系**；AIR 约束与批次 STARK 证明当前仍只覆盖 v1
   关系（`StarkCurve` note 的 AIR 约束未扩展）。批次证明对
   migrate/settle-v2 的覆盖是**水位/批次范围级**（§5.2），不覆盖 v2
   验签关系本身。canonical AIR 的 v2 owner 扩展属后续协议升级。
2. **StarknetAccountBinding alpha 限制继承**：验签仍落地为"SNIP-12
   授权摘要格式（canonical 非零 felt）+ 会话密钥（secp256k1 delegated
   key）对 binding 摘要的 ECDSA"；SNIP-12 typed-data 的 keccak 重算、
   授权内 delegated key 与 account 的绑定复核、链上 account contract
   verifier 仍属后续版本；`binding_id` 锚定关系由 registry 侧保证。
3. **MigrateNote 重放的验签边界**：op borsh 载荷不含呈递材料
   （`VerifierMaterial`），WAL 重放侧复核材料无关的全部关系
   （结构/摘要一致性/新鲜度/账本存在性/nonce 查重），加密验签以
   `submit_migrate` 准入路径为准。防线的完整性与 v1 一致地依赖：
   帧由 sequencer 签名（ed25519）、软确认链周期锚定 L1、watcher 等价性
   检测。`SettleV2` 的材料随 op 携带，重放**全量**复核（无此边界）。
4. **v2 结算无 plan**（§4.1）：payout↔seat 投影绑定未覆盖 v2（v2 seat
   生命周期未引入）；v2 输入允许自由余额 note 参与桌结算（桌绑定约束
   仅对 v1 输入保留）。
5. **v2 note 不进 v1 承诺树**：无逐 note 包含证明（客户端凭证路径
   `balances_from_credentials` 仅覆盖 v1）；v2 账本以状态根折叠段承诺。
6. `notes_v2` 采用 BTreeMap、`migration_nonces` 采用 HashSet（状态根
   折叠时排序）：折叠成本 O(n log n)/次提交，账本规模大时的性能优化
   （如增量承诺树）属实现升级，不改语义。

---

## 8. 域标签 / 常量总表（本文冻结）

| 常量 | 值 | 用途 |
|---|---|---|
| `DOMAIN_NOTE_V2_COMMITMENT` | `zchain.note.v2` | NoteV2 承诺 |
| `DOMAIN_NOTE_V2_NULLIFIER` | `zchain.note.v2.nullifier.v1` | NoteV2 nullifier |
| `DOMAIN_NOTE_V2_MIGRATION_NULLIFIER` | `zchain.note.v2.migrate_nullifier.v1` | 迁移消费 nullifier |
| `DOMAIN_NOTE_V2_SETTLE_SCOPE` | `zchain.owner_v2.settle.v1` | v2 结算花费 scope 前缀 |
| `DOMAIN_NOTE_V2_SETTLE_EFFECT` | `zchain.owner_v2.settle.effect.v1` | v2 结算效果摘要 |
| `DOMAIN_OWNER_REF_V2` 等 | 见 `owner_v2.rs` | v2 alpha 冻结（不变） |
| `OWNER_V2_ABI_VERSION` | `2` | MigrateNoteRecord.abi_version 合法值 |
| `default_network_id()` | `blake2s32("zchain-poker-devnet")` | 默认 network id（生产必须显式覆盖） |
| `MigrateNote` 判别值 | `7` | Operation 追加变体 |
| `SettleV2` 判别值 | `8` | Operation 追加变体 |

测试锚：`tests/note_v2.rs::operation_borsh_discriminants_frozen`（判别值
7/8 + v1 判别值不回退）、`tests/owner_v2.rs::borsh_scheme_discriminants_frozen_and_roundtrip`
（scheme 判别值 0/1/2）。
