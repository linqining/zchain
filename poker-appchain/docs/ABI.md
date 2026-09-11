# poker-appchain ABI 规范 v1.2（M0 冻结稿 + v1.1/v1.2 追加字段）

> 状态：2026-09-05 冻结（v1）；v1.1 追加 `hand_proof`；**v1.2（2026-09-12，
> plan-appchain §5.2 P0-1/P0-2/P0-7）追加 `SettlementRecord.plan`、
> `NoteSpec.pot_index/runout_index`、`HandProofBinding.pre/post_state_root`、
> `settlement_binding`/`settle_effect` 新摘要输入、scope v2（canonical 布局）**；
> **v1.2.1 同日追加 §8 REAL 出证策略与 attestation v2.1（plan-appchain
> §5.2-3/P0-3）、§9 提现 finality 门槛（§5.4 配套）**。
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
| 域标签常量 | 见 `felt.rs`：`note.commitment.v1` / `note.nullifier.v1` / `settlement.binding.v1` / `fee.policy.v1` / `spend.digest.v1` / `vault.digest.v1` / `batch_root.v1`；结算结构根（v1.2，见 §4.1）：`zchain.settlement.payout_root.v1` / `zchain.settlement.side_pot_root.v1` / `zchain.texas_poker.settlement_plan.v2`（poker-settlement-core） |

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

rake_of(pot)  = min(pot * rate_bps / 10000, cap)   // 向下取整；Zero 恒 0
split_of(t)   = (t * treasury_bps / 10000, 余数)     // 零头归 operator
commitment    = poseidon(DOMAIN_FEE_POLICY, mode, rate, cap, t_bps, t_x*, t_y*, o_x*, o_y*)
```

- rake_mode 判别值对齐主仓库 `canonical_rake_opening`（NONE=0 / PERCENTAGE=1）。
- 注册表：table_id → 策略，开桌绑定、**无更新路径**（幂等同策略重绑定允许）。

## 4. 结算记录 SettleNotes（M2，v1.2）

```
SettlementRecord {
  table_id: u64
  hand_binding: [u8;32]      // 非零；防重放键
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
8. 费率：`rake.total == plan.rake == policy.rake_of(pot)`；
   `record.policy_commitment == policy.commitment`
   （语义注记：该链要求计划抽水与 appchain 策略在**全额 gross pot** 上一致。
   poker_l1 的 rake 只对 contested 层计费——含 uncalled 返还层的计划其
   plan.rake < policy.rake_of(gross_pot)，会被 fail-closed 拒绝。**已知语义
   缺口**：此类手（含 uncalled 返还）暂不能走 appchain 结算，需后续在
   policy 或 plan 侧统一口径——见 §8.3 前的口径记录与 BLOCKERS.md B9）
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
> 已知边界：rake opening（批级 raked-award 终局）与 contested-only rake
> 计划模型在"sole-survivor 有抽水"终局上语义不一致，此类组合被
> fail-closed 拒绝（见第 8 条注记与 BLOCKERS.md B9），不做放宽。

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

## 10. 指标增量（M9 惯例）

| 名称 | 类型 | 语义 |
|---|---|---|
| `real_settlement_rejected_total` | counter | REAL 结算出证在引擎/提交/批次层被拒 |
| `withdrawal_finality_rejected_total` | counter | REAL note 提现未达 finality 门 |
