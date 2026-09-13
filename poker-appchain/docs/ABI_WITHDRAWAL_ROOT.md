# ABI_WITHDRAWAL_ROOT — withdrawal root + permissionless claim 格式规范

> 状态：2026-09-12 新建（plan-appchain §5.4 / 排期表 §3"withdrawal root +
> permissionless claim"逻辑层）。实现：`poker-appchain/src/withdrawal_root.rs`
> （唯一事实源）+ `vault.rs` 投影挂接。
>
> **域标签收录状态**：本文档的域标签与格式**待 `ABI.md` 统一收录**（作为
> additive 追加章节）；在收录前以本文档 + 代码 golden 测试为契约事实源。
> `ABI.md` 与 `ABI_TE.md` 本体不在本次变更范围内。

## 1. 域标签与哈希原语

| 项 | 值 |
|---|---|
| 域标签 | `zchain.vault.withdrawal_root.v1`（`WITHDRAWAL_ROOT_DOMAIN`，定义于 `withdrawal_root.rs`） |
| 哈希 | sha2-256（`sha2 = { workspace = true }`，workspace 既有依赖；域标签**先置**） |
| 叶前缀 | `0x00`（RFC 6962 风格） |
| 内部节点前缀 | `0x01` |
| 根摘要前缀 | `0x02`（同一域标签下的第三类域分离） |
| 树形状 | 不平衡 → 空叶哈希补齐到 2 的幂（house convention，与 `poker-settlement-core::payout_root` 同构造；哈希族为 sha256 而非 blake2b） |
| 叶序 | 窗口内叶子按 **borsh 编码字节字典序**规范化后建树（顺序无关聚合） |

```
leaf_hash(leaf)     = SHA256(DOMAIN ‖ 0x00 ‖ borsh(leaf))
internal_hash(l, r) = SHA256(DOMAIN ‖ 0x01 ‖ l ‖ r)
empty_leaf_hash     = SHA256(DOMAIN ‖ 0x00 ‖ b"")
root_digest         = SHA256(DOMAIN ‖ 0x02 ‖ height_be(u64) ‖ leaf_count_be(u64) ‖ root)
```

冻结 golden 向量（`withdrawal_root.rs` 单元测试钉住，改动即测试失败）：

| 输入 | 值 |
|---|---|
| `leaf_hash({request_id=01..01, external_recipient=41..41, asset_class=1, amount=500, burned_note_commitment=81..81, checkpoint_height=9})` | `19d3fb2364cde7d1825c07fa8b930a79946c46caa385a32cd65a65dbdb9d6866` |
| 2 叶窗 `{500@01..01, 2350@02..02}` @ height 9 的 `root` | `b6c6f098f5beaaffba3c1e7170293a84c735dd86c4390d0c02335aeaeaf04619` |
| 同窗 `digest` | `8e3cf44238db28bc9e8222148144c5ceef597c0e8b7ac2278f65318c72de9fc5` |

## 2. WithdrawalLeaf（borsh，字段序冻结）

```rust
WithdrawalLeaf {
  request_id: [u8; 32],            // 提现请求幂等键（== vault::WithdrawalRequest.request_id）
  external_recipient: [u8; 32],    // 外部收款地址（抽象 32B）
  asset_class: u8,                 // REAL=1 / PLAY=2（与 note::AssetClass / PayoutLeaf 一致）
  amount: u64,                     // 打款净额（fee 从请求金额内扣后的 payout_amount）
  burned_note_commitment: [u8; 32],// 被销毁 note 承诺（WithdrawRequest op 的 spend.commitment）
  checkpoint_height: u64,          // 承载叶的 checkpoint 高度（分窗键）
}
```

- `amount` 语义为**净额**：M7 提现费从请求金额内扣
  （`payout_amount = amount − flat_fee`，`vault::WithdrawalFeeConfig`），
  叶子承诺对外应付数而非含费数（fee 场景测试钉住）。
- `external_recipient` 为抽象 32B 外部地址；v1 语义 = Starknet 地址字节，
  **felt252 地址映射属链上 Vault 合约阶段**，本层不解释字节内容。
- `checkpoint_height` 同时参与分窗（builder 归窗键）与 claim 摘要重绑定
  （§4）——叶声称的窗口必须与根注册记录一致。

## 3. WithdrawalRoot（checkpoint 携带候选）

```rust
WithdrawalRoot {
  checkpoint_height: u64,  // 窗口高度（== 窗口内全部叶子的 checkpoint_height）
  leaf_count: u64,         // 真实叶子数（不含补齐空叶）
  root: [u8; 32],          // Merkle 根
  digest: [u8; 32],        // 根摘要（§1 公式；claim 台账主键）
}
```

- 聚合：`WithdrawalRootBuilder::push`（按 `checkpoint_height` 归窗，
  `request_id` 全局去重，重复 → `WithdrawalConflict`）→ `build(height)`；
  **空窗不产根**（`Err(OutOfRange)`；`build_all` 跳过空窗）。
- 证明：`merkle_proof(height, leaf_index)`（兄弟路径自叶向根，长度 =
  log2(补齐后宽度)）+ `verify_inclusion(leaf, proof, index, root)`（纯函数；
  `proof.len() >= 64` 或 `index >= 2^len(proof)` 一律 `false`——fail-closed
  形状边界）。
- `leaf_index` 语义 = 叶子在规范化（borsh 字典序）树中的位置，
  `WithdrawalRootBuilder::leaf_index(height, request_id)` 可查。

## 4. Claim 校验链（M7-ACC-5）

`ClaimLedger::claim(root_digest, leaf, proof, index)` 按序执行，任一环
失败即整体拒绝（fail-closed，无部分提交）：

| # | 检查 | 失败错误（stable category） |
|---|---|---|
| 1a | 根 digest 已 `mark_finalized`（未知 digest = 未 finalized） | `RootNotFinalized { digest_hex }` |
| 1b | 摘要重绑定：`digest_of(leaf.checkpoint_height, 注册.leaf_count, 注册.root) == root_digest` | `RootNotFinalized { digest_hex }` |
| 2a | `index < leaf_count`（补齐空叶位不可领取） | `WithdrawalProofInvalid("claim index beyond root leaf_count")` |
| 2b | `verify_inclusion` 通过（叶字段被篡改必在此失败） | `WithdrawalProofInvalid("merkle inclusion proof mismatch")` |
| 3 | `request_id` 未领取过（**Vault 自己检查"未领取"**，§5.4；主键 = request_id，跨根防重放） | `AlreadyClaimed { request_id_hex }` |
| 4 | 标记已领：先落 sidecar（写失败 → `WalCorrupted`、内存不动），再更新内存 | — |

语义要点（M7-ACC-5）：finalized withdrawal 可由用户自行提交 Merkle proof
领取；**重复领取与未 finalized 的根全部拒绝**；校验顺序 1→2→3 意味着被
篡改叶的重放报证明错误（而非重领错误）。

`mark_finalized(&WithdrawalRoot)` 幂等：同 digest 同载荷重复注册返回 Ok、
不重复落账；digest 绑定 (height, count, root) 三元组，载荷冲突在数学上
不可达（哈希碰撞才可能），若出现 → `Codec` Err（fail-closed 防御）。

## 5. Claim sidecar JSONL 契约（冻结）

每行一个紧凑 JSON 对象 + 换行；**字段名/顺序/编码不得变更**：

```text
{"kind":"finalized","digest_hex":"<64hex>","checkpoint_height":<u64>,"leaf_count":<u64>,"root_hex":"<64hex>"}
{"kind":"claimed","request_id_hex":"<64hex>","digest_hex":"<64hex>"}
```

- `digest_hex` / `request_id_hex` / `root_hex`：32B 的 64 字符小写 hex；
  整数为十进制 u64。
- **写入纪律**（与 proven log / proof registry 同口径）：每行完整追加
  （含换行）+ flush；默认不 fsync（`with_fsync(true)` 可开真落盘）。
- **读取容错**（fail-closed 取向）：
  - 文件不存在（首次打开）/ 空文件 → 空状态（合法）；
  - 最后一行无换行（撕裂写）→ **忽略残行 + 告警**（即使恰好可解析），
    且 `open` 在打开追加写端前**物理截断**残行——残行未参与状态，不截断
    则下次追加会拼接在残行上产生损坏合并行；
  - 中间行坏 JSON / 坏 hex / 未知 kind → `Codec` Err（连续前缀承诺已破）；
  - 重放语义：`claimed` 记录先于其 `finalized` 记录、同 request_id 指向
    两个不同 digest → `Codec` Err；同载荷幂等重放 → Ok（重载等价）。
- 重载等价：`open` 与内存写入共用同一状态转移函数——同一 sidecar 重载出
  的台账与原实例在 `finalized_root` / `is_claimed` / 计数上完全一致
  （集成测试 `double_claim_rejected_and_survives_reload` 钉住，含跨实例
  重领仍拒）。

## 6. vault.rs 挂接（投影，非自动触发）

```rust
CustodyLedger::pending_withdrawal_leaves(finalized_below_height: u64) -> Vec<PendingWithdrawal>
PendingWithdrawal { request_id, external_recipient, payout_amount }  // payout_amount = amount − fee（净额）
PendingWithdrawal::into_leaf(asset_class: u8, burned_note_commitment: [u8; 32], checkpoint_height: u64) -> WithdrawalLeaf
```

- 返回全部排队条目（每条在受理时已过 §5.4 finality 门：proven 水位 + 批
  次根）、按 `request_id` 字典序（聚合确定性）；已 `mark_paid` 条目退出投
  影。不做自动触发——由主控在 checkpoint BFT finalized 后拉取并聚合。
- `finalized_below_height` 为调用方声明的已 finalized checkpoint 高度上界。

## 7. 边界与诚实降级点（均属后续阶段，不在本逻辑层）

1. **链上 Vault 合约**：permissionless claim 的合约入口、`external_recipient`
   的 Starknet felt252 地址映射——Vault verifier 阶段。
2. **STARK 验证挂接**：`WithdrawalLeaf` 的出证（REAL note burn → STARK
   proof → BFT finalized checkpoint）在 proof 管道/`real_policy` 侧。
3. **checkpoint 字段集成**：checkpoint v1 尚无 `withdrawal_root` 字段
   （da-selection 报告已指出）；本模块独立定义根，字段集成由主控后续排，
   届时 checkpoint 携带 `WithdrawalRoot`。
4. **队列字段化降级**：v1 提现队列逐条不保留 `asset_class` 与被销毁 note
   承诺（provenance 在受理时消费、不入账），`into_leaf` 由调用方从
   sequencer 的 `WithdrawRequest` op 记录补齐；逐条入队字段化属后续。
   同理 `pending_withdrawal_leaves` 现返回全部排队条目，逐条 checkpoint
   归属过滤待字段集成后收紧。
5. **单写者假设**：sidecar 由调用方保证单写者（与 WAL 纪律一致）。

## 8. 测试映射（回归锚点）

| 语义 | 测试 |
|---|---|
| 域标签/树规则/编码冻结 | `leaf_hash_and_root_golden_vectors`（golden 常量） |
| 聚合确定性（同输入同根/顺序无关/字段敏感/分窗） | `aggregation_deterministic_same_input_same_root`、`aggregation_deterministic_and_order_independent` |
| inclusion 正例（宽 1..=9、全部索引） | `inclusion_proofs_verify_across_widths` |
| 非成员叶拒 | `inclusion_positive_and_non_member_rejected`、`non_member_leaf_rejected` |
| 未 finalized 拒（未知/未注册/叶改窗） | `unfinalized_root_claim_rejected`、`claim_requires_finalized_root_and_rejects_replay`、`claim_rebinds_digest_against_leaf_checkpoint_height` |
| 篡改叶 6 字段逐一拒绝 | `every_tampered_leaf_field_breaks_proof` |
| 重复领拒 + 跨实例重载仍拒 + 重载等价 | `double_claim_rejected_and_survives_reload`、`sidecar_reload_equivalence_and_cross_instance_replay_rejected` |
| sidecar 撕裂尾行/中间行损坏/乱序/双领记录 | `sidecar_torn_tail_ignored_midfile_corruption_fail_closed` |
| fee 场景（含费 → leaf.amount=净额）全链路 | `vault_fee_net_amount_flows_into_leaf_and_claim` |
