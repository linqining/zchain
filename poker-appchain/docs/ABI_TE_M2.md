# ABI TE-M2：REAL 多币种（排期表 §6 TE-M2）

状态：**已实现**（poker-appchain）。设计依据 `docs/plan-token-economy-v1.md`
§2（REAL 多币种现金桌）、§2.2（托管按币种分账 INV-TE-2）、§2.3（出入金
通道）。前置：TE-M1（`AssetId`，`docs/ABI_ASSET_ID.md`）。

纪律基线：零新依赖；fail-closed；v1 与既有 v2 测试零回退（基线 263 →
278，只增不减）；borsh 只追加（判别值 9/10 末位追加，旧字节流解码兼容）。

---

## 1. Operation 判别值（additive，末位追加）

| 判别值 | 变体 | 载荷 | 阶段 |
|---|---|---|---|
| 0..=6 | v1 冻结（OpenTable/CloseTable/Deposit/WithdrawRequest/Transfer/BuyIn/Settle） | — | 不变 |
| 7 | `MigrateNote(Box<MigrateNoteOp>)` | docs/ABI_V2.md | v2 |
| 8 | `SettleV2(Box<SettlementRecordV2>)` | docs/ABI_V2.md | v2 |
| **9** | **`DepositV2(Box<DepositV2Op>)`** | 见 §1.1 | TE-M2 |
| **10** | **`WithdrawRequestV2(Box<WithdrawRequestV2Op>)`** | 见 §1.2 | TE-M2 |

判别值 = 声明序（borsh）；**9/10 冻结**，后续变体只能 ≥ 11 追加。`Box`
仅 Rust 侧布局优化，borsh 编码与裸结构一致（与 7/8 同纪律）。负例回归：
`tests/te_m2.rs::borsh_discriminants_frozen_and_op_shape` 钉住首字节与
v1 判别值不受追加影响。

### 1.1 `DepositV2Op`（判别值 9）

```text
DepositV2Op := {
    deposit_id: [u8; 32],      # 外部充值幂等键（跨版本全局，见 §3）
    owner: OwnerRef,           # 收款人（owner_v2，承诺含 scheme/key_version）
    asset_id: AssetId,         # REAL 域任意已注册 token（NATIVE/USDT/USDC）
    amount: u64,               # > 0
}
```

语义：operator 托管路径（watcher 幂等确认后提交，与 v1 Deposit 同款）。
铸自由余额形态 v2 note（table=None、pot/runout=0；nonce =
`blake2s32("deposit-v2" || seq_be || deposit_id)[..8]` 截断 u64）。

**GAME 域拒入本 op（fail-closed）**：`asset_id.domain != Real` 或 token
未注册（REAL 域封闭枚举外，含 borsh 伪造载荷）→
`AdmissionRejected("op accepts REAL domain registered tokens only")`。
GAME 域发行是 TE-M3 的 `IssueGameToken`（另行追加变体），本 op 不做
GAME 入口。

### 1.2 `WithdrawRequestV2Op`（判别值 10）

```text
WithdrawRequestV2Op := {
    request_id: [u8; 32],          # 提现幂等键（跨版本全局，见 §3）
    owner_sig: SignatureEnvelope,  # v2 信封（owner_v2 验签）
    asset_id: AssetId,             # REAL 域 token（GAME 域拒入本 op）
    gross_amount: u64,             # 提现总额（= 销毁面额；费内扣）
    external_recipient: [u8; 32],  # 外部收款地址
    created_at_ms: u64,            # 受理声明时刻（ms；SLA 起点，随帧确定）
    note: NoteV2,                  # 被销毁 v2 note 全量内容（账本核对）
    nullifier: [u8; 32],           # 声明消费 nullifier（非零，进共享集）
    material: VerifierMaterial,    # 验签材料（随载荷；WAL 重放全量复核）
}
```

任务基线字段（request_id / owner_sig / asset_id / gross_amount /
external_recipient / created_at_ms）之外追加三个机械字段：`note`（销毁
目标，v1 WithdrawRequest 携带 note 同纪律）、`nullifier`（双花防线）、
`material`(验签证据，`SettleInputV2::V2` 同款纪律——**与 MigrateNote 的
submit_migrate 通道不同，本 op 走单一 `Sequencer::submit`，WAL 重放可
全量复核签名**)。边界如实声明：borsh 载荷形状为 TE-M2 首次冻结，若
后续收紧只能升 ABI 版本。

**授权摘要链**（任一环节失配即拒）：

```text
scope  = spend_scope(network_id, OWNER_V2_ABI_VERSION, "withdraw.v2")
effect = blake2s32("effect.withdraw_v2.v2", request_id, borsh(asset_id),
                   gross_amount_be, external_recipient, created_at_ms_be,
                   note.commitment)          # 全语义载荷（S1 纪律）
digest = v2_spend_digest(owner, note.commitment, nullifier, scope, effect)
owner_sig.typed_data_digest == digest       # 否则 digest mismatch
```

**准入清单**（顺序即实现，全 fail-closed，`Sequencer::
apply_withdraw_request_v2`）：REAL 域封闭枚举门 → 面额/资产一致性
（跨 `AssetId` → `AssetMismatch`）→ 信封结构 → signer == note owner →
nullifier 非零/canonical/未消费（`DoubleSpend`）→ 摘要一致 → 新鲜度
（expiry + per-signer nonce 单调，帧时间戳即权威时钟）→ request_id 幂等
（跨版本共享 `withdrawal_ids`）→ 账本核对（存在且内容一致）→ 按 scheme
分派验签。变更段（零失败）：登记 request_id → 推进 v2 nonce 水位 →
`consume_note_v2` → `burned_v2.push((request_id, asset_id, gross))`。

**费语义**：销毁面额 = `gross_amount`；托管打款净额 = gross − fee（per
token 费率，见 §2.3）；withdrawal root 叶承诺**净额**（M7 语义不变）。

## 2. 多币托管（`vault::CustodyLedgerV2`）

v1 `CustodyLedger`（单币标量）冻结不动；TE-M2 新增按 `AssetId` 独立
分账的 `CustodyLedgerV2`——每个 REAL token 一本独立 `TokenCustody`
（储备 / 入金幂等 / 提现队列 / note 绑定互相不可见 = 独立托管的结构表达）。

### 2.1 对账恒等式（per-token，plan §2.2）

```text
delta[token]      = reserved[token] − issued[token]          # 每币种独立，逐日
pending[token]    == pending_payout[token] + pending_fee_float[token]
issued[token]     = live v2 note 面额[token] + burned 毛额[token]
                    （Sequencer::issued_v2_real_by_token 唯一导出口）
```

- 任一 token `delta != 0` → `ReconciliationMismatch`（**整体**拒，逐
  token 判定）；
- GAME 域 v2 note（遗留 PLAY 迁移产物）不入 REAL issued 口径（隔离）；
- `total_by_token()` 只产 per-token 摘要（`TokenCustodySummary`），
  **刻意不提供任何跨 token 合计类型/函数**。

### 2.2 禁止跨币轧差（INV-TE-2，核心负例）

USDT 短库不能用 NATIVE 长库抵。强制点：受理闸门 4（下表）只用**本
token** 的储备与发行；其它 token 的富余在函数内不可见（结构上无法
轧差）。负例钉死：
`tests/te_m2.rs::cross_token_netting_rejected`——USDT 储备 50 / 发行
100、NATIVE 储备 1050 / 发行 1000，合并口径恰平衡（1100 == 1100），
USDT 提现仍 `ReconciliationMismatch{issued:100, reserved:50}` 拒、
NATIVE 同刻放行；`reserve_coverage_is_per_token_no_netting`（vault 单
元）同型。

### 2.3 受理闸门（`enqueue_withdrawal_v2`，顺序即实现）

| # | 闸门 | 失败 |
|---|---|---|
| 1 | REAL 域封闭枚举（GAME 域/未注册 token 拒入本托管） | `OutOfRange` |
| 2 | 幂等先行（per-token；同 id 同载荷 Ok 返还既有条目，异载荷冲突） | `WithdrawalConflict` |
| 3 | finality 门按 **domain**（TE-M1 冻结决策：REAL 域任何 token 走 proven 水位 + 批次根**双门**；幂等命中豁免复审） | `WithdrawalNotFinalized` + `withdrawal_finality_rejected_total` |
| 4 | **储备覆盖核验（轧差拒绝强制点）**：`reserved[token] ≥ issued[token]` | `ReconciliationMismatch` + `withdrawal_reserve_short_rejected_total` |
| 5 | 提现费 per-token（缺省 0；`fee > gross` 拒，`fee == gross` 边界受理=全额抵费；净额 = gross − fee） | `OutOfRange` + `withdrawal_fee_rejected_total` |

- **提现费 per-token 可配**：`with_token_fee(asset, WithdrawalFeeConfig)`
  ——flat fee 以该 token 计价（外部 gas 成本结构不同，plan §2.2）；
  未配置 = 零费（v1 默认语义沿袭）。
- **打款通道 per-token**：`queued_payouts_by_token()` 按 token 分道产出
  打款任务 (request, 净额)；`mark_paid(asset, request_id, tx_hash)` 按
  token 通道确认。NATIVE=原生转账 / USDT/USDC=ERC20 transfer 的链上
  执行器属 **TE-M4 后/部署阶段**（本层只分道，不下链）。
- **SLA**：`sla_report_of(asset, now, threshold)` per-token 独立；
  SLA 起点 = 受理 `now_ms`（生产取 `created_at_ms`——帧链确定值，
  重放等价所需；诚实声明：该时刻是签名覆盖的客户端声明）。

### 2.4 存款幂等（`confirm_deposit_v2`）

per-token：同 deposit_id 同载荷 → Ok（watcher 重试安全）；异载荷 →
`WithdrawalConflict`；note 承诺 per-token 绑定查重。与 v1
`confirm_deposit` 语义逐点一致，账本互不可见。

## 3. 跨版本幂等（deposit_id / request_id 命名空间）

- v2 存款同时查重并插入 v1 `deposit_ids`（共享集）与 v2
  `deposit_records_v2`；v2 提现查重并插入共享 `withdrawal_ids`；
- **v1 路径零变更**（不查 v2 结构）——跨版本重复确认由 v2 侧双向拦截
  （`deposit_v2_idempotent_cross_version_and_vault` 钉住两个方向）；
- `LedgerState` TE-M2 扩展（均**不入状态根**，WAL 重放经 apply 路径
  重建，与 v1 `note_origins`/`burned` 同纪律）：
  - `note_origins_v2: HashMap<[u8;32], u64>`（承诺 → 铸出 op；消费后
    保留——finality 判据输入）；
  - `burned_v2: Vec<([u8;32], AssetId, u64)>`（销毁记录）；
  - `deposit_records_v2: BTreeMap<[u8;32], (AssetId, u64, [u8;32])>`
    （幂等集与载荷一体；托管 confirm 重放/队列重建输入）；
- 导出口：`Sequencer::issued_v2_real_by_token()`、
  `withdrawal_provenance_v2(&NoteV2)`（→ `vault::WithdrawalProvenanceV2
  { asset_id, source_op_index }`）、`LedgerState::deposit_records_v2()`。

## 4. withdrawal root 的 token 维度（leaf 字段演进记录）

**选型：`asset_class` 字节语义扩展为资产标签**（非追加字段）——
`WithdrawalLeaf` borsh 布局与字节编码**完全冻结**（golden 向量零回退）：

| 标签 | 资产 | 来源 |
|---|---|---|
| 1 | REAL/NATIVE | v1 `AssetClass::Real`，字节不变 |
| 2 | GAME/PLAY（遗留） | v1 `AssetClass::Play`，字节不变 |
| 3 | REAL/USDT | TE-M2 新增 |
| 4 | REAL/USDC | TE-M2 新增 |
| ≥5 | GAME 注册表 token | TE-M3 注册表分配（占位，本版不使用） |

- 常量表：`withdrawal_root::leaf_asset_tag`；映射函数：
  `leaf_asset_tag_of(AssetId) -> Option<u8>`（`None` = v1 leaf 编码无
  表示——TE-M3 前 GAME 注册表 token **不得出根**，fail-closed）；
- vault 侧投影：`vault::PendingWithdrawalV2::into_leaf`（净额语义不变，
  资产标签折叠进 `asset_class` 字节）；
- token 维度进叶哈希：同窗混币与纯 NATIVE 窗根不同；换标签即非成员
  （`withdrawal_root_token_dimension_and_legacy_compat` 钉住）。

## 5. 边界（如实声明）

1. **GAME 域发行未实现**：GTS 注册表 / `IssueGameToken` /
   `BurnGameToken` 属 TE-M3；本版 GAME 域对存（DepositV2）、提
   （WithdrawRequestV2）、托管（CustodyLedgerV2）、出根（leaf 标签）
   四口全部拒入（fail-closed）；GAME 域 v2 note 只能经 MigrateNote
   遗留迁移产生，且不可经 v2 提现赎回。
2. **链上打款属 TE-M4 后/部署**：`queued_payouts_by_token()` 只产出
   分道任务快照；原生转账 / ERC20 transfer 执行器、USDT/USDC 外部
   合约地址白名单（运营参数 + 协议常量双层，plan §2.3）、Starknet
   felt252 地址映射均不在本层。
3. **托管账为 sequencer 外挂**（与 v1 同架构，不入状态根）：账本侧 v2
   幂等集/销毁记录/来源映射由 WAL 重放恢复；托管队列由重放后按同一
   受理语义等价重建（`wal_replay_vault_queue_equivalence` 钉住：finality
   证据经 proven-log 恢复后，`total_by_token()` 与分道任务逐项一致）。
4. **v2 note 无拆分**：提现销毁整张 note（v2 Transfer/BuyIn 生命周期
   未引入）；多面额需求由多张 note 表达。
5. **OpenTable.currency 未在本版启用**：桌币种绑定（INV-TE-6）依赖
   v2 BuyIn/seat 生命周期，与 TE-M4 GAME 桌一并落地；TE-M2 交付
   存/提/托管三通道（排期表 TE-M2 行的载荷扩展与分账部分）。
6. **created_at_ms 是签名覆盖的客户端声明**：作为 SLA 计时起点是为
   帧链确定性回放；运营侧 SLA 报告应结合托管受理时钟解读。

## 6. 指标增量（M9 惯例）

| 计数器 | 含义 |
|---|---|
| `ops_deposit_v2_total` | DepositV2 受理成功 |
| `ops_withdraw_v2_total` | WithdrawRequestV2 受理成功 |
| `withdrawal_finality_rejected_total` | finality 门拒（v1/v2 共用语义） |
| `withdrawal_reserve_short_rejected_total` | 储备覆盖核验拒（轧差拒绝面） |
| `withdrawal_fee_rejected_total` | 费 > 金额拒（per-token） |
| `withdrawal_sla_breach_total` | SLA 越限（per-token，一次一计） |

## 7. 测试证据（`tests/te_m2.rs`，15 用例 + vault 单元 6 用例）

- 三币种存/提闭环 + per-token 对账恒平：`three_token_deposit_withdraw_closed_loop`
- 幂等存款（双侧 + 跨版本双向 + vault confirm）：`deposit_v2_idempotent_cross_version_and_vault`
- **跨币轧差拒绝（核心负例）**：`cross_token_netting_rejected`
- per-token 恒等式：`per_token_identity_and_reconciliation`
- 费 per-token 内扣：`withdrawal_fee_per_token_internal_deduction`
- finality 双门 ×3 + GAME 拒入：`finality_gate_dual_gate_all_real_tokens`
- GAME 域准入拒绝（含伪造 token / 迁移产物赎回拒）：`game_domain_rejected_at_admission`
- 信封过期 / nonce 重放 / 摘要篡改 / 材料错配 / 代签：
  `envelope_expired_rejected`、`envelope_nonce_replay_rejected`、
  `envelope_digest_and_material_tamper_rejected`
- 双花：`same_note_double_withdraw_rejected`
- WAL 重放恢复（幂等集/销毁/来源/状态根逐位）：`wal_replay_restores_v2_idempotency_and_burn_records`
- WAL + proven log 托管队列等价重建：`wal_replay_vault_queue_equivalence`
- root token 维度 + 旧编码零回退：`withdrawal_root_token_dimension_and_legacy_compat`
- 判别值冻结 + op 形状：`borsh_discriminants_frozen_and_op_shape`
