# poker-appchain ABI 规范 v1.3（M0 冻结稿 + v1.1/v1.2 追加字段 + v1.2.2 语义修正 + v1.2.3 追加章节 + v1.2.4 v2-alpha 附录 + v1.3 洗牌/发牌证明链消费面）

> **评审记录（M0-ACC-2，2026-09-13 归档）**：本规范 v1.3（含 v1.2.4
> additive 附录 §14 v2-alpha）经实现-规范一致性核对评审通过——评审范围
> 覆盖 Note / FeePolicy / 软确认帧三节字段与版本号、判别值冻结表、
> §5.2-2 结算语义引用；核对证据 = 判别值冻结测试
> `fee.rs::borsh_discriminants_are_frozen`、batch/aggregate/crypto-statement
> 三处 golden 向量、additive 附录零变更声明（§14）。后续版本变更须按本
> 文 changelog 追加并重走一致性核对。


> 状态：2026-09-05 冻结（v1）；v1.1 追加 `hand_proof`；**v1.2（2026-09-12，
> plan-appchain §5.2 P0-1/P0-2/P0-7）追加 `SettlementRecord.plan`、
> `NoteSpec.pot_index/runout_index`、`HandProofBinding.pre/post_state_root`、
> `settlement_binding`/`settle_effect` 新摘要输入、scope v2（canonical 布局）**；
> **v1.2.1 同日追加 §8 REAL 出证策略与 attestation v2.1（plan-appchain
> §5.2-3/P0-3）、§9 提现 finality 门槛（§5.4 配套）**；
> **v1.2.2（2026-09-12，BLOCKERS B9）修正 rake 计费口径为 contested-only
> （`rake.total == plan.rake == policy.rake_of(plan.rake_base())`）——纯
> 语义修正，wire format 不变**；
> **v1.2.3（2026-09-12，M4 outer aggregate + explorer E2 闭环）追加
> §11 聚合根（aggregate root：域标签 + 折叠算法 + `AggregateRecord`）、
> §12 proof 归档注册表 JSONL 契约、§13 explorer 网关端点表——全部为
> additive 追加，无任何既有字段/域标签/语义变更**；
> **v1.2.4（2026-09-12，plan-appchain §6.12.1b "完整路径"第一步）新增
> §14 ABI v2 alpha 附录（OwnerRef / SignatureEnvelope / MigrateNote、
> 三 scheme 判别值与域标签、MigrateNote 校验关系）——纯 additive：
> v2-alpha 类型仅定义 + 校验，未接 v1 Operation 准入，v1 Note ABI
> 零变更**；
> **v1.3（2026-09-13，设计文档 `docs/shuffle-deal-proof-design.md`
> §5-C2/C3 + 上游 stage0 实测收口）新增 §15 洗牌/发牌证明链消费面：
> 状态镜像承诺偏移（90/122/154/186）、hand_binding v2 升域与三态
> 迁移、deck 链摘要冻结算法（上游 poseidon 折叠同源裁决）、全链
> fail-closed 强制（含 REAL×协议行 11b-f）、crypto receipt 门与上游
> `engine_receipt_digest` 语义对齐、`SequencerConfig` 两个默认关的
> enforcement 开关**（变更记录见文末 changelog）。
> 所有跨边界结构走 borsh；本文档是 wire format 的唯一事实源。任何变更必须
> 升版本号（`.v2` 域标签 / 新枚举变体）；v1.2 均为 borsh 尾缀字段追加，
> 未部署前无兼容包袱。

## 1. 编码原语

| 原语 | 规则 |
|---|---|
| 哈希 | `starknet_crypto::poseidon_hash_many`（多元素）；`blake2s-256`（字节摘要） |
| 32B → 域输入 | **hi/lo 拆分**：`(bytes[0..16], bytes[16..32])` 两个 felt（无损） |
| felt → 32B | 裸 `to_bytes_be`（域元素 < p < 2^252，可逆）；反向只接受 < p 的字节（fail-closed） |
| 域分隔标签 | `poseidon(hi, lo)`，hi/lo = blake2s32(domain_utf8) 拆分 |
| 域标签常量 | 见 `felt.rs`：`note.commitment.v1` / `note.nullifier.v1` / `settlement.binding.v1` / `fee.policy.v1` / `spend.digest.v1` / `vault.digest.v1` / `batch_root.v1` / `aggregate_root.v1`（v1.2.3，§11）；结算结构根（v1.2，见 §4.1）：`zchain.settlement.payout_root.v1` / `zchain.settlement.side_pot_root.v1` / `zchain.texas_poker.settlement_plan.v2`（poker-settlement-core）；v2-alpha（v1.2.4，`owner_v2.rs`，§14）：`zchain.owner_v2.owner_ref.v1` / `zchain.owner_v2.spend.v1` / `zchain.owner_v2.migrate.v1` / `zchain.owner_v2.binding.v1` |

> ⚠️ 历史教训（已修复）：不得用 `byte0 & 0x03` 掩码编码——starknet 域元素
> 可达 2^251（byte0 ∈ {0x04..0x07}），掩码丢位导致承诺不可逆。

## 2. Note（M1）

```
Note {
  asset_class: u8        // 1 = REAL, 2 = PLAY（borsh use_discriminant=true）
  amount: u64            // > 0
  owner: [u8; 33]        // secp256k1 压缩公钥
  nonce: [u8; 32]        // 铸币方生成，全局唯一
  table_id: Option<u64>  // Some = 桌内 seat note
}

commitment = poseidon(DOMAIN_NOTE_COMMITMENT, class, amount,
                      x_hi, x_lo, y_hi, y_lo, nonce_hi, nonce_lo, table)
             // x/y 来自 owner 压缩公钥的无损 32B 拆分；table: 0=None, id+1=Some
nullifier  = poseidon(DOMAIN_NOTE_NULLIFIER, commitment, secret_hi, secret_lo)
             // spend_secret 由 owner 客户端派生（账本不持有）
```

- 承诺树：深度 32 Poseidon Merkle（`merkle.rs`），叶 = commitment felt；
  包含证明兄弟路径为 32B 规范编码。
- nullifier 集根：插入序确定性折叠 `root_i = poseidon(root_{i-1}, nf_i)`。
- 零值拒绝：amount == 0、nullifier 全零（griefing 防御）。

## 3. FeePolicy（M5）

```
enum FeePolicy {
  Zero,
  FixedRake { rate_bps: u16(≤10000), cap: u64(0=无封顶), split: FeeSplit }
}
FeeSplit { treasury_bps: u16(≤10000), treasury: [u8;33], operator: [u8;33] }

rake_of(base) = min(base * rate_bps / 10000, cap)   // 向下取整；Zero 恒 0
split_of(t)   = (t * treasury_bps / 10000, 余数)     // 零头归 operator
commitment    = poseidon(DOMAIN_FEE_POLICY, mode, rate, cap, t_bps, t_x*, t_y*, o_x*, o_y*)
```

- **rake 计费基数（v1.2.2，B9 口径统一）**：`rake_of` 的输入 `base` 是
  **rake 基数**——结算路径传 `plan.rake_base()`（poker-settlement-core
  `SettlementPlan::rake_base()`：plan 内 **contested 层**（eligible ≥ 2 座）
  的 `gross_amount` 之和）。uncalled 返还层（uncontested）**不计费**：
  `plan.validate` 强制其 rake == 0，故 `plan.rake` 只能来自 contested 层。
  该口径与 poker_l1 canonical（`derive_settlement_plan` 对 contested gross
  取费）**唯一一致**：无 uncalled 层的手二者恒等（rake_base == gross_pot）。
- rake_mode 判别值对齐主仓库 `canonical_rake_opening`（NONE=0 / PERCENTAGE=1）。
- 注册表：table_id → 策略，开桌绑定、**无更新路径**（幂等同策略重绑定允许）。

## 4. 结算记录 SettleNotes（M2，v1.2）

```
SettlementRecord {
  table_id: u64
  hand_binding: [u8;32]      // 非零；防重放键（v1.3 起三态分类与 v2 升域
                             // 见 §15.2：v2 = deck 链绑定，v1 = batch_digest）
  policy_commitment: [u8;32] // 必须等于桌绑定策略承诺
  pot: u64                   // 本手下注额；v1.2 起必须 == plan.gross_pot
  inputs:  Vec<SettleInput>  // SettleInput { note: Note, spend: SpendAuth }
  payouts: Vec<NoteSpec>     // v1.2：与 plan 投影一一对应（见下）
  rake: RakeSplitRecord { total, treasury_out: Option<NoteSpec>, operator_out }
  plan: SettlementPlan       // v1.2 追加（borsh 尾缀）——poker-settlement-core
                             // 类型（结算语义唯一事实源，plan-appchain §5.2-1）
  hand_proof: Option<HandProofBinding>   // v1.1 追加字段
}
NoteSpec { asset_class, amount, owner, table_id,
           pot_index: u8, runout_index: u8 }  // v1.2 追加两字段；非结算输出恒 0/0
SpendAuth { commitment: [u8;32], nullifier: [u8;32], sig: EcdsaSig(64B compact) }
HandProofBinding { archive_bytes: Vec<u8>, post_state_commitment: [u8;32],
                   pre_state_root: [u8;32], post_state_root: [u8;32] }  // v1.2 追加两根
```

### 4.1 v1.2 结算结构根（plan-appchain §5.2-1/2/7）

三个 32B 根把结算**从已验证状态派生**并**完整绑定输出结构**：

| 根 | 算法 | 域标签 |
|---|---|---|
| `plan_digest` | `blake2b-256(DOMAIN ‖ borsh(SettlementPlan))`（poker-settlement-core `SettlementPlan::digest`；跨组件唯一事实源，**域标签冻结不变**） | `zchain.texas_poker.settlement_plan.v2` |
| `payout_root` | 叶子按 borsh 字节序排序后建 RFC 6962 树：叶子 `H(0x00‖leaf_borsh)`、内部 `H(0x01‖l‖r)`、每次哈希调用整体前缀域标签；空树 `H(0x00‖b"")`、单叶 `H(0x00‖leaf)`、不平衡以空叶哈希补齐到 2 的幂（与 `poker_l1/offline/ack_chain.rs` 同一 house convention） | `zchain.settlement.payout_root.v1` |
| `side_pot_root` | `blake2b-256(DOMAIN ‖ borsh(plan.pots))`（分层结构承诺） | `zchain.settlement.side_pot_root.v1` |

`PayoutLeaf { asset_class: u8, amount: u64, owner: [u8;33], table_id: u64,
pot_index: u8, runout_index: u8 }`——赔付的**完整绑定**（P0-7：不能只签
owner 和金额）。`settlement_binding`（Poseidon）在 rake.total 之后追加三个
根（各 32B hi/lo 无损拆分）；`settle_effect`（blake2s）在 rake.total 之后
追加 `payout_root`（32B）。

哈希选型记录：plan/payout/side-pot 根用 **blake2b-256 + 域标签**（字节对象，
与 VM/归档栈一致）；AIR 绑定层（承诺树/批次根/结算绑定/策略承诺）用
**Poseidon252**。两层不混用。

**校验关系（顺序即实现，全部 fail-closed）**：
1. hand_binding 非零；inputs 非空
2. `plan.validate(inputs.len())` 通过（版本 / 座位·层数边界 / gross=rake+awards /
   层内守恒 / runout 投影规范；poker-settlement-core 单一实现）
3. `plan.gross_pot == record.pot`（**pot 从已验证计划派生**，不再独立可信）
4. 每个 input：note.table_id == record.table_id；同类；commitment 匹配；
   nullifier 非零；且 **`Σinputs == plan.gross_pot`**（seat note 即本手下注贡献）
5. 输出同类、非零；每个 payout 的 table_id 为 None 或 `Some(record.table_id)`
6. payouts 与 plan 投影**一一对应**：期望三元组 `(pot_index, runout_index,
   seat, amount)` 按 `(pot,runout,seat)` 规范序从 plan 展开（只含 active
   runout 槽位与非零 award）；声明顺序给出 owner↔seat 映射（k-th payout ↔
   k-th 三元组）；`(pot_index, runout_index, amount)` 逐项相等（索引越界即
   投影不符）；owner↔seat 一一对应；按 owner 聚合 == `plan.awards`
7. P 层签名（v1.1）：owner ECDSA over
   `spend_digest = blake2s(DOMAIN_SPEND_DIGEST, commitment, nullifier, scope, effect)`，
   scope = `DOMAIN_SETTLEMENT_BINDING || hand_binding`；
   **effect = settle_effect(record)** = blake2s(`poker-appchain.settle.effect.v1`,
   hand_binding, pot, Σinput commitments, Σoutputs(owner,amount), rake.total,
   **payout_root**〔v1.2〕)——签名绑定精确赔付结构（P0-7），sequencer 无法
   改打给别人；policy_commitment 刻意不在 effect 内，由注册表冻结检查
   （第 8 条）独立强制
8. 费率（v1.2.2/B9 口径）：`rake.total == plan.rake ==
   policy.rake_of(plan.rake_base())`；
   `record.policy_commitment == policy.commitment`
   （**rake 基数 = contested 层 gross 之和**（`SettlementPlan::rake_base()`），
   uncalled 返还层不计费——`plan.validate` 已强制 uncontested 层 rake == 0，
   与 poker_l1 canonical 的 contested-only 计费同口径；v1.2.1 前误按全额
   gross pot 计费导致含 uncalled 返还层的合法手被 fail-closed 拒绝，v1.2.2
   修正。计费口径收敛不放松任何其他防线：`plan.gross_pot == record.pot ==
   Σinputs == 镜像 pot`（第 3/4/11 条）与分账绑定（第 10 条）不变——即
   gross 全额仍全额守恒，rake 只从 contested 基数计征）
9. 守恒：`Σinputs == Σpayouts + Σrake_notes`（rake note 已含在输出侧）
10. 分账：treasury_out/operator_out 数额 == `policy.split_of(rake.total)` 且收款人匹配
11. 手牌证明绑定（v1.1/v1.2，可选）：`hand_proof` 存在时，归档 scope
    （**scope v2** = canonical 布局镜像，见 §4.2）必须满足：
    table_id 一致；终态承诺 == 声明值；**pre/post_state_root == 声明值**
    （v1.2）；transition_count > 0；**gross_pot 逐字节绑定**（v1.2，P0-2）：
    解析 `post_state_image_bytes` 中偏移 74 的 8 字节 LE `pot`，断言
    == `record.pot`；归档含 `rake_opening` 时断言 `record.rake.total` ==
    `min(floor(pot·bps/10⁴), cap, pot)`（mode 0 → 0；与 poker_texas_air
    `canonical_settlement_rake` 同式）。**完整 STARK 验证**由
    `poker-appchain-texasair` 适配器 crate 的 `TexasAirEngine` 执行
    （`verify_canonical_tagged_proof`）

> v1.2 关闭 BLOCKERS B2 末段：终态承诺 → pot 数值的逐字节绑定经由
> `post_state_image_bytes`（被 Fiat--Shamir 范围绑定 + 端点投影约束）
> 中 `pot` 字段的直接解析完成。
> 已知边界（v1.2.2 更新）：rake opening（批级 raked-award 终局，计费基数 =
> 终态全池 pot）与 contested-only 计划模型在"含 uncalled 返还层的 raked
> 终局"上基数不同，此类组合仍被 fail-closed 拒绝（不放宽）；终局**无**
> uncalled 层时 `pot == plan.rake_base()`，rake opening 与 `plan.rake` 恒等
> 复现（B9 已关闭主体口径缺口，见 BLOCKERS.md）。

### 4.2 TexasArchiveScope v2（canonical 布局镜像）

`TexasArchiveScope`（borsh）字段序与
`poker_texas_air::texas_canonical_air::ArchivedCanonicalTaggedProof` 公开
字段序**逐字段一致**：

```
log_size: u32, num_columns: u32, table_id: u64,
first_hand_id: u32, last_hand_id: u32, first_call_seq: u32, last_call_seq: u32,
transition_count: u16, first_transition_kind: u8, last_transition_kind: u8,
reveal_timeout_cascade_count: u8, reveal_timeout_cascade_schedule: [u8; 9],
batch_digest: [u8;32], pre_state_commitment: [u8;32], post_state_commitment: [u8;32],
pre_state_root: [u8;32], post_state_root: [u8;32],
pre/post_lifecycle_root, pre/post_overlay_root, pre/post_settlement_commitment,
pre/post_custody_commitment（各 [u8;32]）,
pre_state_image_bytes: Vec<u8>, post_state_image_bytes: Vec<u8>,
range_claimed_sum: [u32;4],
rake_opening: Option<RakeOpeningScope{ rake_mode: u8, rake_bps: u16, rake_cap: u64 }>,
blind_opening: Option<BlindOpeningScope{ small_blind: u64, big_blind: u64, ante_mode: u8, ante_amount: u64 }>
```

尾部字段（`rules_hash` / `state_object_key` / `state_opening_epoch` /
`stark_proof_bytes`）不镜像：borsh 结构解码不消费尾缀字节。镜像一致性由
适配器测试（真实归档 → `parse_archive_scope` 逐字段比对 + 镜像 pot 偏移
断言）钉住。

状态镜像内偏移（`CanonicalStateImage` v5 定宽 borsh ABI，1,680 字节，
u64 LE）：`chip_pool` @ 66、`pot` @ 74。

## 5. 软确认帧（M3）

```
SoftConfirmFrame { index: u64, prev_hash: [u8;32], op: Operation,
                   state_root: [u8;32], ts_ms: u64 }
SignedFrame { frame, sig: [u8;64] }   // ed25519 over blake2s(borsh(frame))
```

- 创世帧：index 0，prev_hash 全零；链校验 `verify_chain` 全量重验。
- 状态根：`poseidon` 折叠（树根, nullifier 根, 注册表根, 桌折叠, seq,
  spent_count, proven_watermark）——重放逐帧比对（分叉即 WAL 损坏）。

## 6. 操作集 Operation v1（封闭）

`OpenTable{table_id, policy}` · `CloseTable{table_id}` · `Deposit{deposit_id,
owner, asset_class, amount}` · `WithdrawRequest{spend, note, request_id}` ·
`Transfer{spends, notes, outputs}` · `BuyIn{table_id, spends, notes,
seat_owner}` · `Settle(Box<SettlementRecord>)`

scope 标签（防跨操作重放）：`withdraw.v1` / `transfer.v1` / `buyin.v1` /
结算域。新操作 = 协议版本升级，禁止运行时扩展。

## 7. 批次根 BatchRoot（M4，P0-6 冻结）

证明批次（`pipeline::BatchRoot`）锚定到 L1 的承诺值。**哈希函数统一为
Poseidon**（`starknet_crypto::poseidon_hash_many`，与本链状态根、承诺树、
nullifier 折叠同一实现；历史版本曾误用 blake2s，已废弃）。批内结算按帧序
（`op_index` 升序、无空洞）排列为 `bindings = [b_1, …, b_n]`：

```
fold_0 = 0                                   // FieldElement::ZERO
fold_i = poseidon_hash_many([fold_{i-1}, hi_i, lo_i])
                                             // binding 32B 按 §1 纪律 hi/lo 无损拆分
                                             // hi_i = b_i[0..16]，lo_i = b_i[16..32]
batch_root = felt_to_bytes32(poseidon_hash_many([D, fold_n]))
D = poseidon(hi, lo)，hi/lo = blake2s32("poker-appchain.batch_root.v1") 拆分（§1 域分隔标签）
```

- 域标签：`poker-appchain.batch_root.v1`（`felt::DOMAIN_BATCH_ROOT`）。
- 空批次不产生批次根（batch_size ≥ 1）；n ≥ 2 时 fold 严格依赖绑定序
  （交换两帧 binding 得到不同根）。
- golden vector：`pipeline.rs` 测试 `batch_root_golden_vector`——
  bindings = `[0xAA;32], [0xBB;32]` 时
  `batch_root = 00f6fae93ff03c440c1136a5d8b5eab742f07c268c52536d4932ce4171933c52`。
- ABI 版本：**v1**（域标签后缀 `.v1`）。哈希函数/域标签/编码任一变更必须
  升 `.v2` 并同步本节与 `pipeline::batch_root` 实现。

## 8. REAL 结算出证策略与 attestation v2.1（P0-3，plan-appchain §5.2-3）

### 8.1 RealSettlementPolicy（`poker_appchain::real_policy`）

```
enum RealMode { Disabled, HostAttestation, StarkRequired }   // 默认 = StarkRequired
struct RealSettlementPolicy {
  mode: RealMode,
  verifier_key: Option<[u8; 32]>   // 固定 attestor 公钥（生产注入）
}
```

| mode | 允许出证 REAL 的引擎 | verifier_key |
|---|---|---|
| `Disabled` | 无（熔断：拒绝一切 REAL 出证） | — |
| `HostAttestation` | `host-validate-v2`、`texas-air-*` | 可选 |
| `StarkRequired`（**默认**） | `texas-air-*`（真实 STARK 验证路径） | **必须 Some** |

fail-closed 默认：`StarkRequired` + `verifier_key = None` → **REAL 结算全部
拒绝**。放宽（`HostAttestation`/`Disabled`）必须显式配置。

### 8.2 三层强制门（全部默认收紧，拒绝路径唯一变体）

1. **引擎层**：`ValidationEngine::prove` 对输入资产类为 REAL 的记录一律返回
   `RealRequiresStarkProof`（host 签名引擎天然不能给 REAL 出证，与管道配置
   无关）。REAL 的"已证明"必须真实经过 `texas-air-*` 引擎的 stwo 验证路径。
2. **管道提交层**（`ProofPipeline::submit`，单实例单引擎 → 拒绝尽早）：
   REAL 结算 op 要求 ① 模式允许当前引擎、② 引擎名带 `texas-air-` 前缀、
   ③ StarkRequired 已钉 verifier key、④ 携带 `hand_proof`，否则
   `RealRequiresStarkProof` / `AdmissionRejected("real settlement requires
   hand proof")`，任务不进队列。
3. **批次/水位层**（`ProofPipeline::try_build_batch` 出队前）：REAL op 的
   bundle 复查引擎允许集与 attestor 钉扎；违反 →
   `RealRequiresStarkProof` / `VerifierKeyMismatch`，completion 原地保留——
   该 op **不得标记已证明**、水位不推进，计 `real_settlement_rejected_total`。

指标：`real_settlement_rejected_total`（提交/批次/引擎层 REAL 拒绝合计）。

### 8.3 texas-air attestation v2.1

- 域标签：`poker-appchain.texas-air-v2`（**不变**；版本区分靠消息形状与
  payload 定长，v2 的 128B 载荷与 v2 签名对 v2.1 一律失败）。
- 消息：`blake2s32([domain ‖ binding(32) ‖ post_state_commitment(32) ‖
  post_state_root(32) ‖ pre_state_root(32) ‖ plan_digest(32)])`。
  相对 v2 追加 `pre_state_root`（归档 scope）与 `plan_digest`
  （`poker-settlement-core::SettlementPlan::digest`，§4.1；取值时该计划已
  通过 `validate_settlement` 校验）。
- payload（定长 **192B**）：

```
[0..32]    post_state_commitment   // 已验证终态承诺
[32..64]   post_state_root         // 已验证终态 SMT 根
[64..96]   pre_state_root          // 已验证首态 SMT 根（v2.1 新增）
[96..128]  plan_digest             // 已验证结算计划摘要（v2.1 新增）
[128..192] ed25519 签名（attestor）
```

- P0-3 四要素覆盖：**verifier key**（隐含于签名者 + §8.2 钉扎检查）、
  **引擎版本**（bundle `engine` 字段 = 域标签族）、**pre/post 状态根**、
  **已验证结算计划摘要**。
- 钉扎：`TexasAirEngine::with_verifier_key(key)` 后，`verify` 对
  `bundle.attestor_public != key` 返回 `VerifierKeyMismatch`（引擎侧强制，
  与 §8.2 第 3 层互为冗余防线）。
- ABI 版本：**v2.1**（引擎名仍为 `texas-air-v2`；消息/payload 形状变更，
  未部署前无兼容包袱）。

## 9. 提现 finality 门槛（§5.4 配套）

- **provenance**：`LedgerState.note_origins: note 承诺 → 铸出 op`（`mint_note`
  写入，**消费后不删除**——提现销毁后托管打款侧仍可查；WAL 重放重建）。
  查询入口 `Sequencer::withdrawal_provenance(note)`；账本外 note 无
  provenance，无法构造门槛证据。
- **批次根证据**：sequencer 维护 `through_op → batch_root` 内存映射
  （`Sequencer::record_batch_root` / `mark_proven_through_with_root`，生产
  装配点在证明管道批次回调一次调用）；重启后由管道对已验证批次重新回调
  恢复（与 proven 水位同生命周期）。
- **托管侧门槛**：`CustodyLedger`（`withdrawal_requires_finality`，默认
  **true**）。REAL note 提现申请要求来源 op 同时满足：
  1. `proven_watermark >= op_index`（连续前缀语义 = 该 op 已证明）；
  2. 已记录批次根覆盖该 op（`batch_covered_through = Some(t)`，`t >= op`；
     批次侧用 `Option` 存在性判定——op 0 与"尚无批次根"在裸数值下不可
     区分，None 一律拒绝）。
  未满足 → `WithdrawalNotFinalized { op_index, watermark }`，计
  `withdrawal_finality_rejected_total`。幂等语义保持：已受理的同 id 同载荷
  重复申请直接返回既有条目（不受门槛复审影响）。
- **PLAY note 豁免**（软确认即可提，§5.1 分层）。
- `withdrawal_requires_finality = false`（`CustodyLedger::without_finality_gate`）
  为**显式 opt-out，仅限测试/开发，非生产配置**。

### 9.1 提现费（M7，v1 托管侧定价——非 wire format）

`WithdrawalFeeConfig { flat_fee: u64 }`（`vault.rs`）为**托管账侧**配置，
默认 `flat_fee = 0`（免费，完全向后兼容）。语义：

- 受理时费用**从被提现余额内扣**：`fee = flat_fee`、打款净额
  `payout_amount = amount − fee`；链上销毁面额（`WithdrawRequest.note.amount`）
  与操作编码**不变**——本节不引入任何新字段/域标签/操作；
- **负例 fail-closed**：`flat_fee > amount` → 拒绝（`OutOfRange`），计
  `withdrawal_fee_rejected_total`，条目不入账；
- 对账恒等式保持：`delta = reserved − issued` 与零费时完全一致；排队额
  浮存侧分解 `pending_withdrawal_total == pending_payout_total +
  pending_fee_float`（对外应付净额 + 留存费用浮存）；
- SLA 计时（M7-ACC-2/M9）：提现条目记录受理时刻 `requested_at_ms`（注入
  时钟，生产默认 `SystemTime`）；`sla_report(now_ms, threshold_ms)` 输出
  排队数/越限数/等待 p95，越限首次发生计 `withdrawal_sla_breach_total`
  （同一请求不重复计数）。

## 10. 指标增量（M9 惯例）

| 名称 | 类型 | 语义 |
|---|---|---|
| `real_settlement_rejected_total` | counter | REAL 结算出证在引擎/提交/批次层被拒 |
| `withdrawal_finality_rejected_total` | counter | REAL note 提现未达 finality 门 |
| `proof_registry_write_failed_total` | counter（v1.2.3） | proof 归档注册表 sidecar 写失败（完成项不吞，仅告警） |
| `aggregate_log_write_failed_total` | counter（v1.2.3） | aggregate-log sidecar 写失败（本实例挂起聚合记录） |
| `withdrawal_fee_rejected_total` | counter（§9.1） | 提现费超过请求金额被拒（fail-closed 负例） |
| `withdrawal_sla_breach_total` | counter（§9.1） | 排队提现等待超阈值（首次越限计数，不重复） |
| `table_ops_total{table_id}` 等 per-table 族 | counter/gauge（§9.1 配套 M9） | 每桌操作/结算计数（`table_settlements_total`）与瞬时 gauge；桌数上限 4096，超限新桌拒绝并计 `table_metrics_overflow_total` |

## 11. 聚合根 aggregate root（M4 outer aggregate，v1.2.3 追加）

批次根序列（§7 的 `BatchRoot` 按产出序）的**定期二级聚合**承诺值
（`aggregate.rs::aggregate_roots`）。与 batch_root 同构的确定性 Poseidon
折叠（hi/lo 无损拆分），仅域标签不同：

```
fold_0 = 0
fold_i = poseidon_hash_many([fold_{i-1}, hi_i, lo_i])
                                             // batch_root 32B 按 §1 纪律 hi/lo 拆分
aggregate_root = felt_to_bytes32(poseidon_hash_many([D, fold_n]))
D = poseidon(hi, lo)，hi/lo = blake2s32("poker-appchain.aggregate_root.v1") 拆分
```

- 域标签：`poker-appchain.aggregate_root.v1`（`felt::DOMAIN_AGGREGATE_ROOT`，
  v1.2.3 冻结）。
- **空输入 → Err**（空窗口不产生聚合根，fail-closed）；单根 →
  `fold(0, root)` 仍在独立域下产生与 batch_root 不同的聚合值（域分隔生效）；
  n ≥ 2 时 fold 严格依赖根序（交换两根得到不同聚合根）。
- 触发语义（`ProofPipeline::aggregate_due(now_ms, interval_ms)`）：自上次
  聚合以来已产出的批次根非空**且** `now ≥ 上次 + interval` 时折叠窗口内
  全部批次根并原子推进内部游标（同一 root 不重复聚合；空窗口/时间窗未到
  → `Ok(None)`）。
- 聚合记录（`AggregateRecord`，sidecar/watcher/网关共同数据形状）：

```
AggregateRecord { index: u64, through_op: u64, root: [u8;32], ts_ms: u64, batch_count: u64 }
// index：从 0 起连续递增；through_op：窗口内最后一个批次的 through_op（严格递增）
// batch_count：本窗口折叠的批次根数量
```

- 持久化：`aggregate.log` sidecar（JSONL 契约见 §12.3）；watcher 从
  proven log 取窗口内批次根独立重算比对（不符 → `aggregate_mismatch`，
  exit 1）。
- golden vector：`aggregate.rs` 测试 `aggregate_roots_golden_vector`——
  roots = `[0xAA;32], [0xBB;32]` 时
  `aggregate_root = 02e0fb4c5fd664605e11765c6ad2928346d4f87fc68971c229354576c069a1bd`。
- ABI 版本：**v1**（域标签后缀 `.v1`）。

## 12. proof 归档注册表（E2 闭环，v1.2.3 追加）

### 12.1 JSONL 契约（冻结）

`proof_registry.jsonl`（`proof_registry.rs`），每行一个紧凑 JSON 对象 +
换行；字段名/顺序/编码不得变更：

```text
{"binding_hex":"<64hex>","op_index":<u64>,"engine":"<str>","attestor_public":"<64hex>","payload_b64":"<base64 of archive bytes>"}
```

- `payload_b64` = **标准 base64（RFC 4648，含 `=` 填充、规范尾位）**；
  workspace 无 base64 crate，编解码由 `proof_registry::b64_encode/b64_decode`
  唯一实现（RFC 4648 测试向量钉住）。
- `engine` 不得含 `"` / `\` / 控制字符（单行 JSON 契约形状保证）。
- `binding_hex` 重复追加**允许**（幂等去重由读取方负责）。

### 12.2 写入/读取纪律（与 proven log 同口径）

- 写入：逐行完整追加；默认只 flush 不 fsync（`with_fsync(bool)` 可开真落
  盘）；写失败计 `proof_registry_write_failed_total` 且**不吞完成项**——
  归档是旁路优化，证明水位承诺点仍是 WAL fsync + 批次回调。
- 读取：空文件合法；撕裂尾行忽略 + 告警；中间行坏 JSON/坏 hex/坏 base64
  → Err（fail-closed）。

### 12.3 aggregate log 契约（冻结）

```text
{"index":<u64>,"through_op":<u64>,"root":"<64hex>","ts_ms":<u64>,"batch_count":<u64>}
```

写入方 `sequencer.rs::AggregateLogWriter`；`index` 从 0 起连续递增、
`through_op` 严格递增；容错语义与 §12.2 一致（写失败挂起本实例聚合记录，
计 `aggregate_log_write_failed_total`；恢复走
`Sequencer::replay_restoring_proven_and_aggregates`，既有
`replay_restoring_proven` 签名与语义不变）。

## 13. explorer 网关端点（只读，v1.2.3 整理）

网关为只读 GET 白名单路由（未知路径 404 / 非 GET 405 / 坏参数 400 /
格式合法不存在 404）；全部响应带 `X-Zchain-Gateway: replay-v1`。

| 端点 | 语义 | v1.2.3 状态 |
|---|---|---|
| `/api/v1/status` | 链头/水位/批次根摘要 + `latest_aggregate_root` / `latest_aggregate_through_op`（无则 null） | 追加两字段 |
| `/api/v1/frames` | 软确认帧摘要分页（limit ≤ 200） | v1.2.2 前既有 |
| `/api/v1/settlements` | 结算摘要分页 + `table_id` 过滤 | v1.2.2 前既有 |
| `/api/v1/settlement/{hand_binding}` | 单笔结算全量明细；**追加 `payout_root`**（`payout_root_bytes`，§4.1）与 **`proof` 链接** `{"href":"/api/v1/proof/<binding>","engine":<str>\|null}`（注册表命中时填引擎，否则 null） | 追加两字段 |
| `/api/v1/batch_roots` | proven log 批次根列表 | v1.2.2 前既有 |
| `/api/v1/proofs?offset=&limit=` | proof 归档**元数据**分页（binding/op_index/engine/payload 字节数；不内联 payload；limit ≤ 200） | v1.2.3 新增 |
| `/api/v1/proof/{binding_hex}` | proof 归档**下载**：`{"binding_hex","op_index","engine","attestor_public","payload_b64","payload_len"}`；响应头 `X-Zchain-Engine: <engine>`；坏 hex → 400、未命中 → 404（JSON） | v1.2.3 新增 |
| `/api/v1/aggregates` | M4 outer aggregate 聚合记录列表（index/through_op/root/ts_ms/batch_count） | v1.2.3 新增 |
| `/api/v1/metrics` | 注册表文本导出（replay 静态快照） | v1.2.2 前既有 |
| `/api/v1/l1/{metrics,block,tx}` | L1 JSON-RPC 只读代理（未配置 → 404） | v1.2.2 前既有 |

网关新增启动参数：`--proof-registry <path>`（§12.1）、
`--aggregate-log <path>`（§12.3）；`--gen-fixture` 同步增产
`proof_registry.jsonl`（真实管道出证落档）与 `aggregate.log`。

## 14. ABI v2 alpha：OwnerRef / SignatureEnvelope / MigrateNote（v1.2.4 追加，plan-appchain §6.12.1b "完整路径"第一步）

> **边界声明（先读）**：v2-alpha 类型**仅定义 + 校验**（`owner_v2` 模块），
> **未接 v1 Operation 准入**；**v1 Note ABI（§2-§7）零变更**——
> `Note.owner` 仍为 33B 压缩公钥，v1 承诺/nullifier/spend digest 的域标签
> 与编码不变。本节只构成 v2 正式版的 ABI 前瞻与 AIR witness 形状基线；
> 迁移进 proof/BFT checkpoint、v1 Operation 适配与统一
> SettlementPlanDigest 结算集成均属 v2 正式版范围。

### 14.1 类型（borsh 稳定 ABI，判别值冻结）

```
SignatureScheme        // use_discriminant=true，单字节编码
  LegacySecp256k1 = 0 | StarkCurve = 1 | StarknetAccountBinding = 2
                       // 冻结；新增方案只允许追加新判别值，未定义数值 fail-closed 拒绝

OwnerRef {
  scheme: SignatureScheme
  account_id: [u8;32]        // 语义按 scheme，见下
  key_version: u32           // 参与全部摘要；同公钥换版本即换身份
  binding_id: Option<[u8;32]>  // 仅 StarknetAccountBinding 允许 Some
}

SignatureEnvelope {
  scheme: SignatureScheme          // 必须 == signer_ref.scheme
  signer_ref: OwnerRef
  typed_data_digest: [u8;32]       // 被签摘要；迁移路径下 == migrate_digest
  signature: [u8;64]               // 按 scheme：secp 64B r‖s compact /
                                   // Stark (r,s) 各 32B canonical felt /
                                   // 会话密钥 secp 64B compact
  nonce: u64                       // 单调：严格大于 signer 已见最大值
  expiry: u64                      // unix 秒；now >= expiry 即过期
}

MigrateNoteRecord {
  old_commitment: [u8;32]          // 非零
  old_owner_sig: SignatureEnvelope // 旧 owner 授权
  new_owner_ref: OwnerRef          // 铸出的 v2 note owner
  amount: u64                      // > 0，与旧 note 同额
  asset_class: u8                  // 1=REAL / 2=PLAY（与旧 note 同类）
  migration_nonce: [u8;32]         // 非零；防迁移重放
  network_id: [u8;32]              // 目标 ZChain network id（防跨网重放）
  abi_version: u32                 // 目标 ABI 版本（alpha 恒 2）
}
```

`account_id` 语义按 scheme：

| scheme | `account_id` | `binding_id` |
|---|---|---|
| `LegacySecp256k1`（0） | `blake2s32(压缩公钥 33B)`（32B key-id；验签呈递完整公钥并复核哈希） | 必须 None |
| `StarkCurve`（1） | 规范化 felt252 公钥（非零、< p） | 必须 None |
| `StarknetAccountBinding`（2） | Starknet 账户地址（canonical felt） | 必须 Some（非零，指向 `AuthorizeZChainKey` 授权记录） |

### 14.2 域标签与摘要（全部 Poseidon + hi/lo 无损拆分，输出恒 canonical felt）

| 域标签（冻结） | 用途 |
|---|---|
| `zchain.owner_v2.owner_ref.v1` | `owner_commitment(OwnerRef)`：scheme + key_version + account_id + binding_id 全参与——**同 account_id 跨 scheme/版本承诺必不同** |
| `zchain.owner_v2.spend.v1` | `v2_spend_digest`：owner 承诺 +（note 承诺, nullifier, scope〔blake2s32 后拆分〕, effect）；对应 v1 `poker-appchain.spend.digest.v1` 的 v2 形态 |
| `zchain.owner_v2.migrate.v1` | `migrate_digest(MigrateNoteRecord)`：绑定全部语义字段；**sighash 规则**：`old_owner_sig.typed_data_digest`（必须等于本摘要）与签名字节本身不参与（否则自指循环） |
| `zchain.owner_v2.binding.v1` | `binding_authorization_digest`：(账户地址, binding_id, SNIP-12 授权摘要, 会话密钥公钥, 授权终点) |

### 14.3 三 scheme 验签（alpha 形态）

- **LegacySecp256k1**：呈递压缩公钥 → `blake2s32(pk) == account_id` 复核 →
  ECDSA compact 验证（复用 v1 §2/§4 签名原语）。
- **StarkCurve**：`starknet_crypto::verify(account_id_felt, digest_felt, r, s)`；
  (r, s) 各 32B canonical felt 且非零。
- **StarknetAccountBinding（alpha 降级声明）**：验 SNIP-12 授权摘要格式
  （canonical 非零 felt）+ 重算 binding 摘要 + 会话密钥（SNIP-12 delegated
  key，secp256k1）ECDSA。**完整账户 verifier（SNIP-12 typed-data keccak
  重算以复核授权内 delegated key ↔ account 绑定、链上 account contract
  的多签/Passkey 语义）属 v2 正式版**；alpha 阶段授权真实性与 `binding_id`
  锚定关系由 registry 侧保证。互操作由冻结向量钉住：poker-wallet
  `account_binding`（SNIP-12 rev1）对同一输入的 `AuthorizeZChainKey`
  message hash 与本附录测试向量逐字节一致（见
  `tests/owner_v2.rs::snip12_interop_vector_binding_verification`）。

### 14.4 MigrateNote 语义与校验关系（纯函数，AIR witness 形状就绪）

旧 owner 授权消费旧 note → **同额同资产类**铸 v2 note；迁移必须绑定
`old_commitment`、`new_owner_ref`、`migration_nonce` 与目标
`network_id`/`abi_version`。校验顺序（`validate_migrate_note`，全部
fail-closed）：

1. `old_commitment` 非零；
2. `migration_nonce` 非零；
3. `amount > 0`；
4. `new_owner_ref` 结构合法（account_id 非零 / StarkCurve 规范化 / binding_id 关系）；
5. 信封一致（`scheme == signer_ref.scheme` + signer 合法）；
6. 摘要一致：`old_owner_sig.typed_data_digest == migrate_digest(record)`；
7. 新鲜度：`now < expiry` 且 nonce 严格单调（过期 / 重放拒）；
8. 旧签名按 scheme 分派验签通过（§14.3）。

SNIP-12 互操作 golden vector：域 `Snip12Domain::zchain("zchain-devnet-1")`、
`account_address` = felt `2`、`binding_id` = felt `1`、
`delegated_public_key = 0256b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967`
（= secp256k1 seed `[9;32]` 压缩公钥）、nonce `3`、单笔/日限额 `50/100`、
桌白名单 `[1]`、有效期 `[1000, 2000]` 时，`AuthorizeZChainKey` message hash
= `0108780ad34e8ed9b8cfb3ffefef7a1c0e6134a385200ce93a8820da6bb70436`
（与 poker-wallet acceptance 测试同源复算冻结）。

- ABI 版本：**v2-alpha**（全部域标签后缀 `.v1`；判别值冻结）。任何字段/
  编码/域标签变更必须升版并同步本节。

## 15. 洗牌/发牌证明链消费面（v1.3 追加，设计文档 `docs/shuffle-deal-proof-design.md` §5-C2/C3）

> 上游（poker_texas_air）stage0 实测报告见本目录 `SHUFFLE_STAGE0.md`；
> 消费侧语义与排队清单见 `SHUFFLE_CONSUME.md`。本节冻结跨边界判定面。

### 15.1 状态镜像承诺偏移（`CanonicalStateImage` v5 定宽 borsh，1,680 字节）

| 字段 | 偏移 | 消费侧强制 |
|---|---|---|
| `chip_pool: u64` (LE) | 66 | custody 恒等式（AIR 逐行约束） |
| `pot: u64` (LE) | 74 | **既有 v1.2 锚**：结算记录 pot 逐字节绑定（§4） |
| `board_cards_commitment: [u8;32]` | 90 | 存在性消费（暂无强制） |
| `deck_commitment: [u8;32]` | 122 | **牌序（加密形态）进入镜像的唯一入口**（S1 锚）：pre/post 非零 + v2 绑定覆盖 |
| `reveal_commitment: [u8;32]` | 154 | v2 全链批终态非零（11b-e）；协议行判定输入 |
| `reconstruction_commitment: [u8;32]` | 186 | 存在性消费（重构为可选协议路径） |

偏移推导与镜像一致性：v1.3 起有**双重钉扎**——(a) 消费侧独立手写编码器
（`tests/shuffle_chain_consume.rs::state_image_commitment_offsets_match_documented_layout`）；
(b) **上游真实归档**逐字段钉扎（`poker-appchain-texasair/tests/
shuffle_stage0_consume.rs` 导出 + `poker-appchain/tests/
shuffle_chain_real_archive.rs` 消费，夹具 `tests/fixtures/stage0_full_chain.*`）。

### 15.2 hand_binding v2（升域）与三态迁移

```text
hand_binding_v2 = felt32(poseidon_hash_many(
    domain_felt(b"zchain.settlement.binding.v2"),
    hi/lo(scope.batch_digest),
    hi/lo(deck_chain_digest),          // §15.3 冻结算法
    hi/lo(post.reveal_commitment),
))
```

- 三个数据输入全部重导自归档 scope 公开字段（无生产者信任输入）；
  与上游 `hand_binding.rs`（`poker_dual_hand_binding_v1` 全量布局）为
  **子集对齐**（全量对齐属设计文档 §6-Q3 开放决策）。
- 三态分类（11a）：`HandBindingV2`（= 上式重导）/ `LegacyBatchDigest`
  （= `scope.batch_digest`，v1 e2e 形态）/ `Unbound`（皆非）。
  v2 → 追加 11b 全链强制（§15.4）；Legacy/Unbound → 迁移期接受并计数。
- **迁移窗（默认开）与 receipt 门（默认关）的运营面开关**（additive，
  默认均为 `false` = 现状行为）：
  `SequencerConfig { full_chain_enforcement, crypto_receipt_enforcement }`
  （TE-M2/3/6 同款 additive 字段纪律，逐行注明见 `sequencer.rs`），
  经 `SequencerConfig::apply_settlement_gates()` 在进程启动路径刻入
  settlement 层进程级原子量；**replay/build_index/watcher 重放面禁止
  调用**（`validate_settlement` 在重放 apply 路径上执行，判定必须与帧
  提交时刻一致——WAL 重放确定性，P0-4）。

### 15.3 deck 承诺链摘要（**冻结算法：上游 poseidon 折叠，与生产者同源**）

阶段 0 裁决（2026-09-13，SHUFFLE_CONSUME.md §1.2）：上游 stage0 的真实
洗牌链是权威数据源，消费侧算法必须对上游产出**重导一致**——早期消费侧
blake2b-256 提案（域 `zchain.settlement.deck_chain.v1`）删除，冻结为
上游 `canonical_shuffle_chain` receipt 的逐字节复制：

```text
preimage = b"zchain.texas.canonical-shuffle-chain.v1"  // 上游 SHUFFLE_CHAIN_STAGE0_DOMAIN
         ‖ b"deck-chain"                               // 上游 fold_chain 标签
         ‖ anchor[0] ‖ … ‖ anchor[len-1]               // 链锚 32B 顺次
digest   = poseidon_bytes_digest(preimage)             // u64 长度前缀 felt
                                                       // + 31B 大端分块
                                                       // + poseidon_hash_many
```

- 实现落点：`poker-settlement-core/src/deck_chain.rs`（`deck_chain_digest`；
  空链 / `len > 10` → `None` fail-closed，上限对齐上游
  `MAX_DECK_COMMITMENTS = 10`）；
- **两侧对照证据**：上游真实 `ShuffleChainBuilder`（BG V2 生产域）产出
  的链 → 上游 `ShuffleChainReceipt.deck_chain_digest` vs 消费侧重导
  **逐位一致**（`poker-appchain-texasair/tests/shuffle_stage0_consume.rs`，
  golden `073c5e280d7d548111384f60c97f1b492af20b5d1ef4c242497b55605265e66a`，
  确定性种子可重现）；
- 结算消费面的链 = scope 端点去重 `[pre.deck, post.deck]`（批内逐环链由
  AIR 行内约束 + STARK 验证负责）；上游 receipt 的链锚序列可长于端点链，
  算法同源、输入不同层——两者经同一函数复现。

### 15.4 v2 全链 fail-closed 强制（11b）与 REAL×协议行 fail-closed（11b-f）

对 `HandBindingV2` 记录，在 §4 既有 11 条之上追加（拒绝消息即清单）：

| # | 校验 | 拒绝消息 |
|---|---|---|
| a | 首 kind ∈ {JoinTable(1), StartHand(3), SubmitShuffle(7)} | `full-chain archive first transition kind is not a chain-entry kind` |
| b | 末 kind ∈ {AdvanceRound(19), EndWithoutShowdown(21), RevealTimeoutAward(27), RevealTimeoutRakedAward(28)} | `full-chain archive last transition kind is not settlement-terminal` |
| c | `blind_opening` 存在、ante_mode ≤ 2、非全零 | `full-chain archive is missing the blind opening` / `blind opening has unsupported ante mode` / `blind opening is vacuous (all-zero blinds and ante)` |
| d | pre/post 镜像 deck 承诺非零 | `archive pre-state deck commitment is zero (S1 anchor missing)` / `archive post-state deck commitment is zero` |
| e | 终态 reveal 承诺非零 | `archive terminal reveal commitment is zero (deal not covered)` |
| f | **REAL 类 × 含协议行归档 → 拒绝**（无开关） | `REAL settlement archive contains protocol rows; route A native shuffle-chain verification is required (fail-closed)` |

11b-f 依据（上游 stage0 实测负面发现，SHUFFLE_STAGE0.md §3.4-2）：
canonical AIR 对**非末段** shuffle 行 deck 承诺篡改不可见（AIR 只冻结锚、
不重算密文哈希，篡改批照样出证）——含协议行的 REAL 结算必须经路线 A
原生校验（引擎侧 BG/DLEq 逐行验证 + sidecar 承诺链重导），该结果在结算
纯函数层不可自证 ⇒ 直接拒绝该批（宁可停、不可假）。协议行判定
（`archive_has_protocol_rows`，fail-closed 过近似）：首/末 kind ∈ {7,8,9}
或 deck/reveal/reconstruction 承诺在批内轮转。引擎 receipt 归责接线后
本分支升级为"要求回执集验证"。

### 15.5 路线 B：crypto receipt（语句面 + 覆盖记账 + 门）

- 语句面（消费侧冻结）：`crypto_statement_digest(kind, inputs) =
  blake2b-256(b"zchain.settlement.crypto_statement.v1" ‖ kind ‖ inputs)`，
  kind ∈ {`bg.shuffle.v2`, `dleq.reveal.v1`}；`expected_crypto_statements`
  给出 scope 级粗粒度期望集（每批每类一条）；`verify_receipt_set` 做覆盖
  记账（恰一回执 / 无未知 / 无重复 / 非零）。**不是密码学验证**——方程
  验证在引擎侧（上游 Plan D 分工）。
- 回执 `receipt_digest` 语义（上游 stage0 已冻结）：
  = `ShuffleChainReceipt.engine_receipt_digest` =
  `poseidon_bytes_digest(DOMAIN ‖ b"receipt" ‖ batch_digest ‖
  deck/reveal/reconstruct 三链摘要 ‖ 逐行 statement_digest)`，域同
  §15.3；逐行 statement digest =
  `poseidon_bytes_digest(DOMAIN ‖ kind ‖ seat ‖ pre ‖ post)`（kind ∈
  {`shuffle`,`reveal`,`reconstruct`}）。消费侧逐行对账需归档携带协议行
  明细（sidecar vs 扩归档 = 设计文档 §6-Q2，未决）——冻结前 receipt 门
  开启即显式拒绝（`crypto receipt enforcement is enabled but engine
  receipt integration is pending upstream stage0`），不许假验证。

## 16. 变更记录（changelog）

### v1.3（2026-09-13）— 洗牌/发牌证明链消费面（设计文档 §5-C2/C3 + 上游 stage0 收口）

- **新增 §15**：状态镜像承诺偏移表（90/122/154/186，与 66/74 并列，
  真实归档双重钉扎）；hand_binding v2 升域（域
  `zchain.settlement.binding.v2`，可重导子集折叠）与三态迁移；deck 链
  摘要冻结算法（**上游 poseidon 折叠同源裁决**，域
  `zchain.texas.canonical-shuffle-chain.v1`，早期 blake2b 提案删除；
  两侧逐位一致对照测试 + golden 钉扎）；全链 fail-closed 强制 11b
  a–e 与 **REAL×协议行 11b-f**（stage0 负面发现的链侧执行，无开关）；
  crypto receipt 门与上游 `engine_receipt_digest` 语义对齐。
- **`SequencerConfig` additive 运营开关**：`full_chain_enforcement` /
  `crypto_receipt_enforcement`（**默认均 false = 现状行为**，逐行注明；
  经 `apply_settlement_gates` 启动面接线，重放面禁用——重放确定性）。
- **TE-M5 缺口收口**：archive_index 补齐全部 v2 op kind 的索引行解析
  （`MigrateNote|SettleV2|DepositV2|WithdrawRequestV2|RegisterGameToken|
  IssueGameToken|BurnGameToken|FaucetMint|BuyGasCredits|BindGasPolicy`
  + `v2` 等价键/金额摘要子对象；格式标签保持 `.v1` 的裁决见
  `archive_index.rs` 模块文档——纯加法、既有文件零影响，v2 WAL 此前
  `--write-index` 直接失败、从未产出过索引文件）。
- **additive 声明**：v1 Note ABI（§2-§7）与既有域标签零变更；scope
  前缀消费零改动；全部新校验只收紧不放宽（REAL×协议行条目对既有
  v1/v2 流量零影响——既有归档均无协议行）；既有测试零回退
  （poker-appchain 364 基线 + 新增用例全绿）。

### v1.2.4（2026-09-12）— ABI v2 alpha 附录（plan-appchain §6.12.1b "完整路径"第一步，纯 additive）

### v1.2.4（2026-09-12）— ABI v2 alpha 附录（plan-appchain §6.12.1b "完整路径"第一步，纯 additive）

- **新增 §14 v2-alpha 附录**：`OwnerRef`（scheme/account_id/key_version/
  binding_id）、`SignatureEnvelope`（scheme 自描述签名信封）、
  `MigrateNoteRecord`（旧 note 授权消费 → 同额同资产类铸 v2 note）三类
  borsh 稳定类型；`SignatureScheme` 判别值冻结（LegacySecp256k1=0 /
  StarkCurve=1 / StarknetAccountBinding=2）。
- **新增域标签（冻结）**：`zchain.owner_v2.owner_ref.v1` /
  `zchain.owner_v2.spend.v1` / `zchain.owner_v2.migrate.v1` /
  `zchain.owner_v2.binding.v1`——全部 Poseidon + hi/lo 无损拆分；
  owner_commitment / spend digest / migrate digest 均显式携带 scheme +
  key_version（防同公钥跨验证器同承诺）。
- **三 scheme 验签 alpha 形态**：Legacy secp256k1（呈递公钥哈希复核 +
  ECDSA）、StarkCurve（starknet-crypto 直接验证）、StarknetAccountBinding
  （验 SNIP-12 授权摘要格式 + 会话密钥签名；完整账户 verifier 属 v2
  正式版——降级点已在 §14.3 明示）。SNIP-12 rev1 `AuthorizeZChainKey`
  互操作 golden vector 与 poker-wallet `account_binding` 同源冻结一致。
- **MigrateNote 校验关系**：旧承诺/迁移 nonce 非零、amount>0、expiry
  未过、nonce 单调、`typed_data_digest == migrate_digest`、旧签名按
  scheme 验签通过、new_owner_ref 合法（纯函数，AIR witness 形状就绪）。
- **边界（不放松任何 v1 防线）**：v2-alpha 类型仅定义 + 校验，未接 v1
  Operation 准入；v1 Note ABI（§2-§7）零变更——无既有字段增删、无既有
  域标签变更、既有 checkpoint 格式不变；全部变更为新增模块
  （`owner_v2`）+ 新增测试（`tests/owner_v2.rs`，12 用例）。
- **测试**：三 scheme 正例 + 篡改负例（换 scheme 字节 / 换 version /
  过期 / nonce 重放）、owner_commitment 跨 scheme 分离、migrate 每字段
  篡改拒、SNIP-12 互操作冻结向量、borsh 判别值与 roundtrip。

### v1.2.3（2026-09-12）— M4 outer aggregate + explorer E2 闭环（纯 additive）

- **新增 §11 聚合根**：域标签 `poker-appchain.aggregate_root.v1`（冻结）+
  与 batch_root 同构的 Poseidon 折叠 + `AggregateRecord` 数据形状 +
  `ProofPipeline::aggregate_due` 定期触发语义；持久化由
  `sequencer::attach_aggregate_log` sidecar 承担，恢复走新增
  `replay_restoring_proven_and_aggregates`（既有恢复函数签名不变）；watcher
  新增 `--aggregate-log` 独立重算校验（`aggregate_mismatch` /
  `aggregate_range` findings，exit 1）。
- **新增 §12 proof 归档注册表**：`ProofBundle` 的 JSONL 归档契约（标准
  base64 载荷，RFC 4648 向量钉死）+ `ProofPipeline::attach_proof_registry`
  挂账（drain 路径旁路归档，写失败不吞完成项）。
- **新增 §13 网关端点**：`/api/v1/proofs`、`/api/v1/proof/{binding_hex}`
  （`X-Zchain-Engine` 响应头）、`/api/v1/aggregates`；`/api/v1/status` 追加
  `latest_aggregate_root` / `latest_aggregate_through_op`；
  `/api/v1/settlement/{binding}` 追加 `payout_root` 与 `proof` 链接。
- **additive 声明**：无既有字段增删/语义变更、无既有域标签变更、既有
  `checkpoint`（`zchain.appchain.checkpoint.v1`）格式不变；全部变更为新增
  模块（`aggregate` / `proof_registry`）、新增 sidecar 契约与新增只读端点。
- **测试**：aggregate golden/空输入/序敏感；pipeline 聚合触发（时间窗、
  空窗口、不重复聚合）与归档挂账；sequencer aggregate-log 契约/恢复等价/
  撕裂与损坏负例；watcher aggregate 正例 + 换根/跳 index/缺 proven log
  负例（exit 1）；网关 proofs/aggregates 端点与 E2 闭环（fixture →
  settlements → payout_root → 归档下载 → 404/400）。

### v1.2.2（2026-09-12）— rake 计费口径统一（BLOCKERS B9 关闭）

- **语义修正**：结算费率关系从 `rake.total == plan.rake ==
  policy.rake_of(record.pot)`（全额 gross pot 口径）改为
  `rake.total == plan.rake == policy.rake_of(plan.rake_base())`
  （**contested-only 口径**：基数 = contested 层 gross 之和，uncalled 返还
  层不计费）。对齐 poker_l1 canonical（`derive_settlement_plan` 只对
  contested gross 取费）。
- **行为变化边界**：仅限"此前被误拒的合法手（含 uncalled 返还层）现在可
  结算"。此前被拒的手（篡改 rake、分账不符、跨层挪 rake、低报 pot）仍然
  全拒：uncontested 层 rake == 0 由 `plan.validate` 强制（跨层挪 rake 到
  uncalled 层不可行），gross 全额守恒（第 3/4/9/11 条）与分账/收款人绑定
  （第 10 条）不变。
- **wire format 不变**：无字段增删、无域标签变更；`rake_base` 是已验证
  计划的派生量（`SettlementPlan::rake_base()`），不入编码。
- **测试**：core（rake_base 单测 + derive uncalled 层锚点）、poker_l1
  （canonical uncalled 层测试钉住 contested-only 基数）、appchain
  （uncalled 层结算正例 + 负例矩阵回归）、texasair e2e（含 uncalled 层的
  REAL 结算流）。

### 未升版补充（2026-09-12）— M7 提现费 / 提现 SLA / M9 per-table 指标 / E2 archive 索引（全部非 wire format）

以下为**文档级补充**，不升 ABI 版本号：全部为托管账侧配置、库内指标或
只读工具面，未新增/变更任何 borsh 结构、操作集、域标签或链上编码
（wire format 与 v1.2.4 完全一致；§13 端点表新增可选启动参数见下）。

- **§9.1 提现费**（新增小节）：`WithdrawalFeeConfig { flat_fee }`（托管
  账侧定价，默认 0 = 免费；费从被提现余额内扣，打款净额 = amount − fee；
  费 > 金额 fail-closed 拒绝）；对账恒等式不变 + 排队额浮存侧分解；
  提现 SLA 计时（`requested_at_ms` 注入时钟 + `sla_report` +
  `withdrawal_sla_breach_total`）。
- **§10 指标表追加**：`withdrawal_fee_rejected_total` /
  `withdrawal_sla_breach_total` / per-table 指标族
  （`table_ops_total{table_id}` 等，上限 4096 桌，超限计
  `table_metrics_overflow_total`）。
- **E2 archive 索引**（实现契约冻结于 `poker-appchain/src/archive_index.rs`
  模块文档，非 ABI 对象）：`zchain.appchain.archive_index.v1` JSONL 契约
  （头部行 chain_head/counts/digest + 每帧一行
  `{kind,index,ts_ms,state_root,hash,offset}`（Settle 附摘要）+ Proof 行；
  digest = blake2s-256(头部行之后全部原始字节)）；网关新增 `--index-file`
  （免 replay 直连查询，status 链头取自索引头部行）与 `--write-index`
  （回放构建落盘）启动参数——只读查询面参数，不涉及链编码。
