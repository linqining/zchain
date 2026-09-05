# poker-appchain ABI 规范 v1（M0 冻结稿）

> 状态：2026-09-05 冻结。所有跨边界结构走 borsh；本文档是 wire format 的
> 唯一事实源。任何变更必须升版本号（`.v2` 域标签 / 新枚举变体）。

## 1. 编码原语

| 原语 | 规则 |
|---|---|
| 哈希 | `starknet_crypto::poseidon_hash_many`（多元素）；`blake2s-256`（字节摘要） |
| 32B → 域输入 | **hi/lo 拆分**：`(bytes[0..16], bytes[16..32])` 两个 felt（无损） |
| felt → 32B | 裸 `to_bytes_be`（域元素 < p < 2^252，可逆）；反向只接受 < p 的字节（fail-closed） |
| 域分隔标签 | `poseidon(hi, lo)`，hi/lo = blake2s32(domain_utf8) 拆分 |
| 域标签常量 | 见 `felt.rs`：`note.commitment.v1` / `note.nullifier.v1` / `settlement.binding.v1` / `fee.policy.v1` / `spend.digest.v1` / `vault.digest.v1` |

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

## 4. 结算记录 SettleNotes（M2）

```
SettlementRecord {
  table_id: u64
  hand_binding: [u8;32]      // 非零；防重放键
  policy_commitment: [u8;32] // 必须等于桌绑定策略承诺
  pot: u64                   // 本手下注额（rake 基数）
  inputs:  Vec<SettleInput>  // SettleInput { note: Note, spend: SpendAuth }
  payouts: Vec<NoteSpec>     // NoteSpec { asset_class, amount, owner, table_id }
  rake: RakeSplitRecord { total, treasury_out: Option<NoteSpec>, operator_out }
  hand_proof: Option<HandProofBinding>   // v1.1 追加字段
}
SpendAuth { commitment: [u8;32], nullifier: [u8;32], sig: EcdsaSig(64B compact) }
HandProofBinding { archive_bytes: Vec<u8> /* borsh */, post_state_commitment: [u8;32] }
```

**校验关系（顺序即实现，全部 fail-closed）**：
1. hand_binding 非零；inputs 非空
2. 每个 input：note.table_id == record.table_id；同类；commitment 匹配；nullifier 非零
3. P 层签名（v1.1）：owner ECDSA over
   `spend_digest = blake2s(DOMAIN_SPEND_DIGEST, commitment, nullifier, scope, effect)`，
   scope = `DOMAIN_SETTLEMENT_BINDING || hand_binding`；
   **effect = settle_effect(record)** = blake2s(`settle.effect.v1`, hand_binding,
   pot, Σinput commitments, Σoutputs(owner,amount), rake.total)——签名绑定
   全部分配语义，sequencer 无法改打给别人（S1）；policy_commitment 刻意
   不在 effect 内，由注册表冻结检查（第 6 条）独立强制
4. 输出同类、非零
5. 守恒：`Σinputs == Σpayouts + Σrake_notes`（rake note 已含在输出侧）
6. 费率：`rake.total == policy.rake_of(pot)`；`record.policy_commitment == policy.commitment`
7. 分账：treasury_out/operator_out 数额 == `policy.split_of(rake.total)` 且收款人匹配
8. 手牌证明绑定（v1.1，可选）：`hand_proof` 存在时，归档 scope（borsh 镜像
   `TexasArchiveScope`）必须满足 table_id 一致、终态承诺 == 声明值、
   transition_count > 0。**完整 STARK 验证**由 `poker-appchain-texasair`
   适配器 crate 的 `TexasAirEngine` 执行（`verify_tagged_texas_proof`）

> 已知边界（B2 剩余尾巴）：v1.1 后 pot 已在 effect 签名与归档终态承诺
> 双重覆盖之下，但"终态承诺 → pot 数值"的逐字节绑定（状态镜像哈希复算）
> 仍缺——需要 poker_texas_air 公开范围暴露 pot 或可复算镜像。见 BLOCKERS B2。

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
