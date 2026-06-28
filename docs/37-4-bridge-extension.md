# 跨链桥扩展文档（含安全约束）

> SubTask 37.4：poker_l1 跨链桥扩展设计文档
>
> 实现来源：`poker_l1/src/bridge/mod.rs`、`poker_l1/src/error.rs`、`poker_l1/tests/bridge_helpers.rs`
>
> 规范依据：`spec.md`（FROZEN 2026-06-27）第 893-907 行（Task 34 跨链桥）

---

## 1. 概述

poker_l1 跨链桥（Bridge）模块提供了与外部异构链之间的资产跨链转移能力。其核心设计目标：

- **资产跨链转移**：支持外部链资产 → poker_l1（mint wrapped 对象），以及 poker_l1 → 外部链（burn wrapped 对象解锁原始资产）
- **2/3 quorum 验证**：每条外部链注册独立的桥验证器集，需达到 `ceil(n * 2 / 3)` 签名 quorum 才能放行存款
- **重放保护**：通过 `nonce` + `chain_id` 双重隔离，并由 `consumed_nonces` / `consumed_burn_nonces` 严格跟踪
- **域分隔签名**：`BRIDGE_SIG_DOMAIN=0x42` 与 `BURN_PROOF_DOMAIN=0x62` 防止跨协议重放
- **recipient 抢跑防护**：`bridge_verify` 必须由 recipient 本人签名提交（SEC2-M1）

桥接模块的协议层入口 `bridge_verify` **禁止由合约直接调用**（SubTask 34.2），合约层调用应返回 `BridgeVerifyNotAuthorized`。所有验证流程必须在协议层 deposit 流程中触发。

### 安全约束总览

| 约束 ID | 描述 | 实现位置 |
|---------|------|---------|
| SEC-H3 | 签名绑定补全 `recipient` + `source_tx_hash` | `BridgeDeposit::message_hash` |
| SEC2-M1 | `bridge_verify` 须 recipient 签名 + preferred_relayer | `bridge_verify` |
| SubTask 34.2 | 协议层调用强制 | `bridge_verify(is_protocol_caller)` |
| SubTask 34.3 | 签名绑定 `(nonce, source_chain_id, dest_chain_id, asset, amount, recipient, source_tx_hash)` | `BridgeDeposit` |
| SubTask 34.4 | burn-on-source + burn proof | `burn_on_source` |
| SubTask 34.5 | 桥验证器插槽注册 | `BridgeValidatorSlot` |

---

## 2. 桥接模型

### 2.1 核心数据结构

#### BridgeDeposit（跨链存款凭证）

定义于 `poker_l1/src/bridge/mod.rs:56-72`。表示源链上一笔跨链存款的全部上下文，桥验证器对该凭证签名背书。

| 字段 | 类型 | 说明 |
|------|------|------|
| `nonce` | `u64` | 源链上的唯一 nonce（防重放） |
| `source_chain_id` | `ChainId` | 源链 chain_id |
| `dest_chain_id` | `ChainId` | 目标链 chain_id（poker_l1） |
| `asset` | `Hash` (32B) | 源链上的合约地址 / token id |
| `amount` | `u64` | 存款金额 |
| `recipient` | `Address` (20B) | poker_l1 上的接收地址（SEC-H3：tagged pubkey 派生） |
| `source_tx_hash` | `Hash` (32B) | 源链上的交易哈希（SEC-H3：跨链追踪） |

#### BridgeVerifyTx（bridge_verify 交易）

定义于 `poker_l1/src/bridge/mod.rs:105-119`。 recipient 提交给 poker_l1 协议层的跨链验证请求。

| 字段 | 类型 | 说明 |
|------|------|------|
| `deposit` | `BridgeDeposit` | 存款凭证 |
| `validator_signatures` | `Vec<BridgeValidatorSig>` | 桥验证器签名集（多签背书） |
| `recipient_sig` | `Vec<u8>` | recipient 本人签名（SEC2-M1：防抢跑） |
| `recipient_pubkey` | `TaggedPubkey` | recipient 的 tagged pubkey（验证 recipient_sig） |
| `preferred_relayer` | `Option<TaggedPubkey>` | 优先 relayer（获额外奖励；None 表示无优先） |

`BridgeValidatorSig`（`poker_l1/src/bridge/mod.rs:122-128`）：

| 字段 | 类型 | 说明 |
|------|------|------|
| `validator` | `TaggedPubkey` | 验证器 tagged pubkey |
| `signature` | `Vec<u8>` | 签名字节（secp256k1：65B `r‖s‖v`） |

#### BurnProof（Burn 证明）

定义于 `poker_l1/src/bridge/mod.rs:136-152`。反向跨链操作：在 poker_l1 上 burn wrapped 对象后生成的证明，提交至源链以解锁原始资产。

| 字段 | 类型 | 说明 |
|------|------|------|
| `burn_nonce` | `u64` | poker_l1 上的唯一 nonce（防重放） |
| `source_chain_id` | `ChainId` | 源链 chain_id（资产原始链） |
| `dest_chain_id` | `ChainId` | 目标链 chain_id（poker_l1，burn 发生链） |
| `asset` | `Hash` (32B) | 资产标识 |
| `amount` | `u64` | burn 金额 |
| `recipient` | `Address` (20B) | 源链上的接收者 |
| `burn_tx_hash` | `Hash` (32B) | poker_l1 上的 burn tx 哈希 |

#### BridgeValidatorSlot（桥验证器插槽）

定义于 `poker_l1/src/bridge/mod.rs:178-186`。每条外部链可注册独立的桥验证器集。

| 字段 | 类型 | 说明 |
|------|------|------|
| `source_chain_id` | `ChainId` | 源链 chain_id |
| `validators` | `BTreeSet<TaggedPubkey>` | 注册的桥验证器 pubkey 集合 |
| `quorum` | `usize` | 所需 quorum 数（2/3 of validators） |

#### BridgeRegistry（桥注册表）

定义于 `poker_l1/src/bridge/mod.rs:260-268`。维护所有已注册的桥验证器插槽与防重放状态。

| 字段 | 类型 | 说明 |
|------|------|------|
| `slots` | `BTreeMap<ChainId, BridgeValidatorSlot>` | 按 source_chain_id 索引的插槽 |
| `consumed_nonces` | `BTreeSet<(ChainId, u64)>` | 已消费的存款 nonce（防重放） |
| `consumed_burn_nonces` | `BTreeSet<(ChainId, u64)>` | 已消费的 burn nonce |

### 2.2 BridgeHook trait

定义于 `poker_l1/src/bridge/mod.rs:236-255`。实现者通过此 trait 注册新桥并定义特定于源链的验证逻辑。

```rust
pub trait BridgeHook: Send + Sync {
    /// 返回源链 chain_id。
    fn source_chain_id(&self) -> ChainId;

    /// 验证桥存款凭证的签名背书。
    fn verify_deposit(&self, deposit: &BridgeDeposit, sigs: &[BridgeValidatorSig]) -> PokerL1Result<()>;

    /// 验证 burn proof（SubTask 34.4）。
    fn verify_burn(&self, burn: &BurnProof) -> PokerL1Result<()>;
}
```

---

## 3. 域分隔与签名

### 3.1 域分隔常量

定义于 `poker_l1/src/bridge/mod.rs:36-39`：

```rust
/// 桥签名域分隔前缀。
const BRIDGE_SIG_DOMAIN: u8 = 0x42; // 'B' for Bridge

/// Burn proof 域分隔前缀。
const BURN_PROOF_DOMAIN: u8 = 0x62; // 'b' for burn
```

### 3.2 消息哈希构造

`BridgeDeposit::message_hash`（`poker_l1/src/bridge/mod.rs:82-96`）：

```
message_hash = blake2b_256(
    BRIDGE_SIG_DOMAIN
    || nonce           (8B LE)
    || source_chain_id (8B LE)
    || dest_chain_id   (8B LE)
    || asset           (32B)
    || amount          (8B LE)
    || recipient       (20B)
    || source_tx_hash  (32B)
)
```

`BurnProof::message_hash`（`poker_l1/src/bridge/mod.rs:157-171`）：

```
message_hash = blake2b_256(
    BURN_PROOF_DOMAIN
    || burn_nonce       (8B LE)
    || source_chain_id  (8B LE)
    || dest_chain_id    (8B LE)
    || asset            (32B)
    || amount           (8B LE)
    || recipient        (20B)
    || burn_tx_hash     (32B)
)
```

### 3.3 域分隔的安全意义

| 域 | 前缀 | 用途 |
|----|------|------|
| `BRIDGE_SIG_DOMAIN` (0x42) | 'B' | 桥验证器对存款凭证的签名 |
| `BURN_PROOF_DOMAIN` (0x62) | 'b' | burn proof 的消息哈希 |

域分隔前缀作为 Blake2b 输入的首字节，保证：

1. **防跨协议重放**：同一密钥对桥签名的消息哈希与 burn proof 的消息哈希必然不同，即使所有其他字段相同
2. **防跨域碰撞**：与 DAG vertex 签名域、ACK 签名域等互不重叠
3. **签名不可复用**：攻击者无法将 burn proof 的签名重新包装成存款凭证签名

---

## 4. Quorum 机制

### 4.1 quorum 计算

定义于 `poker_l1/src/bridge/mod.rs:218-224`：

```rust
pub const fn required_bridge_quorum(validator_count: usize) -> usize {
    if validator_count == 0 {
        return 0;
    }
    (validator_count * 2).div_ceil(3) // ceil(n * 2 / 3)
}
```

### 4.2 quorum 示例

| 验证器数 n | ceil(n * 2 / 3) | 容错 Byzantine 节点数 |
|------------|----------------|---------------------|
| 0 | 0 | 0 |
| 1 | 1 | 0 |
| 3 | 2 | 1 |
| 5 | 4 | 1 |
| 7 | 5 | 2 |
| 10 | 7 | 3 |
| 21 | 14 | 7 |

### 4.3 与 DAG 共识 quorum 的一致性

桥验证器 quorum 严格遵循 `ceil(n * 2 / 3)` 公式，与 DAG 共识中 commit certificate 的 2/3 quorum（见 `poker_l1/src/error.rs:185-187` `InsufficientQuorum`）一致。该设计保证：

- 单一 Byzantine 容错阈值贯穿整个协议栈
- 桥验证器集变更与主链 validator 集变更采用相同的 quorum 计算
- 治理参数调整时可复用 quorum 校验逻辑

### 4.4 quorum 校验 API

```rust
impl BridgeValidatorSlot {
    pub const fn has_quorum(&self, sig_count: usize) -> bool {
        sig_count >= self.quorum
    }

    pub fn validate_signers(&self, sigs: &[BridgeValidatorSig]) -> PokerL1Result<()> {
        for sig in sigs {
            if !self.validators.contains(&sig.validator) {
                return Err(PokerL1Error::BridgeValidatorSlotNotRegistered(sig.validator.clone()));
            }
        }
        Ok(())
    }
}
```

`validate_signers` 在 quorum 计数之前执行，确保所有签名者均属于注册集合（防止未注册验证器的签名被计入 quorum）。

---

## 5. 跨链存款流程

### 5.1 流程图

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│   源链       │         │ 桥验证器集    │         │ poker_l1     │
│ (source)     │         │ (validators) │         │ (dest)       │
└──────┬───────┘         └──────┬───────┘         └──────┬───────┘
       │                        │                        │
   ① 锁定资产                  │                        │
   ② 生成 BridgeDeposit ──────►│                        │
       │                        │                        │
       │                   ③ 签名背书 (2/3)              │
       │                        │                        │
       │ ◄──────────────────────┘                        │
       │                                                │
       │ ④ recipient 提交 BridgeVerifyTx ──────────────►│
       │    (含 validator_sigs + recipient_sig)         │
       │                                                │
       │                                          ⑤ bridge_verify
       │                                            - dest_chain_id 校验
       │                                            - nonce 未消费校验
       │                                            - recipient 签名校验
       │                                            - quorum + 签名校验
       │                                            - 标记 nonce 已消费
       │                                                │
       │                                          ⑥ 铸造 wrapped 对象
       │                                             给 recipient
       │                                                │
```

### 5.2 步骤详解

#### ① 源链锁定资产

用户在源链上调用源链的桥合约，锁定（或 burn）原生资产。源链生成唯一的 `nonce` 与 `source_tx_hash`。

#### ② 生成 BridgeDeposit

源链桥合约构造 `BridgeDeposit`，包含 `nonce`、`source_chain_id`、`dest_chain_id`（poker_l1）、`asset`、`amount`、`recipient`（poker_l1 地址）、`source_tx_hash`。

#### ③ 桥验证器签名背书

桥验证器集监听源链事件，独立验证存款后对 `deposit.message_hash()` 签名。达到 `required_bridge_quorum(n)` 个签名后形成有效背书。

#### ④ recipient 提交 BridgeVerifyTx

recipient 在 poker_l1 上提交 `BridgeVerifyTx`：

- `deposit`：存款凭证
- `validator_signatures`：桥验证器签名集
- `recipient_sig`：recipient 对 `deposit.message_hash()` 的签名（SEC2-M1 防抢跑）
- `recipient_pubkey`：recipient 的 tagged pubkey
- `preferred_relayer`：可选的优先 relayer

#### ⑤ poker_l1 协议层 bridge_verify

调用 `bridge_verify`（`poker_l1/src/bridge/mod.rs:333-409`），按顺序校验：

1. `is_protocol_caller == true`（SubTask 34.2：拒绝合约直接调用 → `BridgeVerifyNotAuthorized`）
2. `deposit.dest_chain_id == network_chain_id`（防跨链重放）
3. nonce 未被消费（`is_nonce_consumed` → `BridgeNonceConsumed`）
4. recipient 签名有效（`verify_signature(recipient_pubkey, recipient_sig, deposit_msg_hash)`）
5. `derive_address(recipient_pubkey) == deposit.recipient`（防 pubkey/地址不匹配）
6. source_chain_id 对应的 slot 已注册（否则 `BridgeValidatorSlotNotRegistered`）
7. 所有签名者均在 slot 中（`validate_signers`）
8. 签名数 ≥ quorum（`has_quorum`）
9. 每个验证器签名有效（`verify_signature`）
10. 标记 nonce 已消费（`consume_nonce`）
11. 返回 `BridgeVerifyOutcome`，由协议层执行铸造

#### ⑥ 资产铸造

协议层根据 `BridgeVerifyOutcome` 铸造对应 wrapped 对象给 `recipient`。

### 5.3 nonce 消费语义

`consumed_nonces` 以 `(source_chain_id, nonce)` 为 key：

- **同一源链**：同一 nonce 不可重复消费
- **不同源链**：同一 nonce 互不冲突（因为 `source_chain_id` 不同）

这实现了 `nonce` + `chain_id` 双重重放保护。

---

## 6. Burn & 提现流程

### 6.1 流程图

```
┌──────────────┐         ┌──────────────┐
│ poker_l1     │         │   源链       │
│ (burn side)  │         │ (release)    │
└──────┬───────┘         └──────┬───────┘
       │                        │
   ① burn wrapped 对象           │
   ② 生成 BurnProof             │
       │                        │
       │ ③ 提交 BurnProof ──────►│
       │                        │
       │                   ④ 验证 BurnProof
       │                      - dest_chain_id 校验
       │                      - burn_nonce 未消费校验
       │                      - 标记 burn_nonce 已消费
       │                        │
       │                   ⑤ 释放原始资产
       │                      给 recipient
       │                        │
```

### 6.2 步骤详解

#### ① poker_l1 burn wrapped 对象

用户在 poker_l1 上 burn 持有的 wrapped 对象，生成唯一的 `burn_nonce` 与 `burn_tx_hash`。

#### ② 生成 BurnProof

构造 `BurnProof`，包含 `burn_nonce`、`source_chain_id`（资产原始链）、`dest_chain_id`（poker_l1）、`asset`、`amount`、`recipient`（源链接收者）、`burn_tx_hash`。

#### ③ 提交 BurnProof 至源链

将 `BurnProof` 提交到源链桥合约。poker_l1 侧通过 `burn_on_source`（`poker_l1/src/bridge/mod.rs:439-464`）同步状态。

#### ④ poker_l1 验证 BurnProof

`burn_on_source` 校验：

1. `burn.dest_chain_id == network_chain_id`（确保 burn 发生在当前链，否则 `BurnProofInvalid`）
2. `burn_nonce` 未被消费（否则 `BurnProofInvalid`）
3. 标记 `burn_nonce` 已消费（`consume_burn_nonce`）

#### ⑤ 源链释放资产

源链桥合约根据 `BurnProof` 释放原始资产给 `recipient`。

### 6.3 burn_nonce 消费语义

`consumed_burn_nonces` 以 `(dest_chain_id, burn_nonce)` 为 key，与 `consumed_nonces` 的 `(source_chain_id, nonce)` 对称：

| 防重放集 | key | 语义 |
|---------|-----|------|
| `consumed_nonces` | `(source_chain_id, nonce)` | 源链存款 nonce |
| `consumed_burn_nonces` | `(dest_chain_id, burn_nonce)` | poker_l1 burn nonce |

---

## 7. 安全约束

### 7.1 重放保护

**机制**：`nonce` + `chain_id` 双重保护。

| 资产方向 | 防重放 key | 校验函数 |
|---------|-----------|---------|
| 存款（源链→poker_l1） | `(source_chain_id, nonce)` | `is_nonce_consumed` / `consume_nonce` |
| Burn（poker_l1→源链） | `(dest_chain_id, burn_nonce)` | `is_burn_nonce_consumed` / `consume_burn_nonce` |

**错误码**（`poker_l1/src/error.rs`）：

- `BridgeNonceConsumed(u64)` — 存款 nonce 已消费
- `BurnProofInvalid(String)` — burn_nonce 已消费时返回此错误

### 7.2 域分隔

**机制**：`BRIDGE_SIG_DOMAIN=0x42` + `BURN_PROOF_DOMAIN=0x62` 防跨协议重放。

- 桥验证器签名对象 = `blake2b_256(BRIDGE_SIG_DOMAIN ‖ deposit_fields)`
- Burn proof 消息哈希 = `blake2b_256(BURN_PROOF_DOMAIN ‖ burn_fields)`
- 两个域前缀不同（'B' vs 'b'），确保即使其他字段完全相同，哈希也必然不同

### 7.3 Quorum（2/3 桥验证器签名）

**机制**：每条外部链的桥验证器集需达到 `ceil(n * 2 / 3)` 个有效签名才能放行存款。

**校验顺序**：

1. `validate_signers`：所有签名者必须在 slot 中
2. `has_quorum(sig_count)`：签名数 ≥ quorum
3. 逐个 `verify_signature`：每个签名必须对应 `deposit.message_hash()`

### 7.4 recipient 签名验证

**机制**：`recipient_sig` + `recipient_pubkey` 防止资产被发送到错误地址（SEC2-M1）。

```rust
// 3. 校验 recipient 签名（SEC2-M1）
let deposit_msg_hash = tx.deposit.message_hash();
verify_signature(&tx.recipient_pubkey, &tx.recipient_sig, &deposit_msg_hash)?;

// 校验 recipient_pubkey 派生地址 == deposit.recipient
let derived_addr = derive_address(&tx.recipient_pubkey);
if derived_addr != tx.deposit.recipient {
    return Err(PokerL1Error::BridgeSignatureInvalid(...));
}
```

**安全意义**：

- 防止第三方抢跑提交 recipient 的存款凭证（抢跑会导致资产被发送到攻击者控制的地址）
- 双重校验：签名有效 + 派生地址匹配，确保 `recipient_pubkey` 与 `deposit.recipient` 一致
- 错误码：`BridgeSignatureInvalid("recipient signature invalid: ...")`

### 7.5 preferred_relayer（前端激励）

**机制**：recipient 可在 `BridgeVerifyTx.preferred_relayer` 中指定优先 relayer，获额外奖励。

- `Option<TaggedPubkey>`：None 表示无优先
- 由协议层在 `BridgeVerifyOutcome` 中传递给 relayer 激励逻辑
- 不影响验证流程，仅作为激励路由提示

### 7.6 协议层调用强制（SubTask 34.2）

**机制**：`bridge_verify` 函数签名包含 `is_protocol_caller: bool` 参数。

```rust
if !is_protocol_caller {
    return Err(PokerL1Error::BridgeVerifyNotAuthorized);
}
```

合约层调用 `bridge_verify` syscall 时，应通过 `bridge_verify_contract_call_denied()`（`poker_l1/src/bridge/mod.rs:488-490`）始终返回 `BridgeVerifyNotAuthorized`。

### 7.7 错误码汇总

| 错误码 | 触发场景 | 来源 |
|--------|---------|------|
| `BridgeVerifyNotAuthorized` | 合约直接调用 `bridge_verify` | `error.rs:543-544` |
| `BridgeSignatureInvalid(String)` | recipient 签名 / 验证器签名 / dest_chain_id 不匹配 / quorum 不足 | `error.rs:546-547` |
| `BridgeNonceConsumed(u64)` | 存款 nonce 已消费 | `error.rs:549-550` |
| `BridgeVerifyNotSignedByRecipient` | （保留）非 recipient 签名 | `error.rs:552-553` |
| `BurnProofInvalid(String)` | burn proof 校验失败 / burn_nonce 已消费 | `error.rs:555-556` |
| `BridgeValidatorSlotNotRegistered(TaggedPubkey)` | 桥验证器未在 slot 中 / slot 未注册 | `error.rs:558-559` |

---

## 8. 桥验证器管理

### 8.1 BridgeValidatorSlot 生命周期

#### 创建

通过 `BridgeValidatorSlot::new(source_chain_id, validators)` 创建，自动计算 quorum：

```rust
let slot = BridgeValidatorSlot::new(source_chain_id, validators);
// quorum = required_bridge_quorum(validators.len()) = ceil(n * 2 / 3)
```

#### 注册

通过 `BridgeRegistry::register_slot(slot)` 注册到桥注册表：

```rust
registry.register_slot(slot);
// 后续可通过 registry.slot(source_chain_id) 查询
```

#### 添加 / 移除验证器

桥验证器集的动态变更需通过重建 `BridgeValidatorSlot` 并重新注册实现：

```rust
// 添加新验证器
let mut new_validators = slot.validators.clone();
new_validators.insert(new_validator_pubkey);
let new_slot = BridgeValidatorSlot::new(slot.source_chain_id, new_validators);
registry.register_slot(new_slot); // 覆盖旧 slot

// 移除验证器
let mut new_validators = slot.validators.clone();
new_validators.remove(&removed_pubkey);
let new_slot = BridgeValidatorSlot::new(slot.source_chain_id, new_validators);
registry.register_slot(new_slot);
```

> **注意**：每次变更后 `quorum` 会基于新集合大小自动重算。生产环境应在变更期间引入 timelock 与多次确认，避免桥验证器集突变。

#### quorum 更新

`quorum` 是派生字段，由 `validators.len()` 计算，无需手动维护。变更 `validators` 后通过 `BridgeValidatorSlot::new` 重建即可。

### 8.2 与主链 validator 集的关系

| 维度 | 主链 ValidatorSet | BridgeValidatorSlot |
|------|------------------|---------------------|
| 范围 | poker_l1 共识 | 单条外部链的桥签名 |
| quorum | 2/3（DAG commit certificate） | 2/3（桥存款背书） |
| 注册位置 | `ValidatorSet`（Task 13） | `BridgeRegistry.slots` |
| slashing | equivocation / VRF 等 | （未来扩展） |
| 独立性 | 与桥验证器集解耦 | 可与主链 validator 重叠或完全独立 |

桥验证器集与主链 validator 集在协议层解耦：

- **可重叠**：主链 validator 可同时担任桥验证器
- **可独立**：可注册完全独立的外部桥验证器集（如由源链桥合约治理的多签方）
- **独立 slashing**：桥验证器的不当行为（如签署无效存款）应由 `BridgeHook::verify_deposit` 实现方负责检测，与主链 slashing（`ValidatorSet` / Task 13）独立

### 8.3 BridgeHook 注册扩展

实现 `BridgeHook` trait 的具体桥可注册到 `BridgeRegistry`，由 `verify_deposit` / `verify_burn` 定义源链特定的验证逻辑（例如源链签名格式、最终性确认深度等）。

---

## 9. 开发示例

### 9.1 完整跨链存款示例

以下示例展示 recipient 在 poker_l1 上提交 `BridgeVerifyTx` 的完整流程。代码参考 `poker_l1/tests/bridge_helpers.rs` 与 `poker_l1/src/bridge/mod.rs` 中的测试用例。

```rust
use poker_l1::account::derive_address;
use poker_l1::bridge::{
    bridge_verify, BridgeDeposit, BridgeRegistry, BridgeValidatorSig,
    BridgeValidatorSlot, BridgeVerifyTx,
};
use poker_l1::signature::{SignatureScheme, CURRENT_VERSION, TaggedPubkey};
use poker_l1::DEFAULT_CHAIN_ID;
use secp256k1::{Message, Secp256k1};
use secp256k1::rand::rngs::OsRng;
use std::collections::BTreeSet;

/// 生成真实的 secp256k1 密钥对。
fn make_keypair() -> (secp256k1::SecretKey, TaggedPubkey) {
    let secp = Secp256k1::new();
    let mut rng = OsRng;
    let (secret, public) = secp.generate_keypair(&mut rng);
    let compressed = public.serialize();
    let tagged = TaggedPubkey::new(
        SignatureScheme::Secp256k1,
        CURRENT_VERSION,
        compressed.to_vec(),
    ).expect("tagged pubkey 构造不应失败");
    (secret, tagged)
}

/// 用 secp256k1 私钥对 msg_hash 签名（r‖s‖v = 65 字节）。
fn sign(secp: &Secp256k1<secp256k1::All>, secret: &secp256k1::SecretKey, msg_hash: &[u8; 32]) -> Vec<u8> {
    let msg = Message::from_digest_slice(msg_hash).unwrap();
    let sig = secp.sign_ecdsa_recoverable(&msg, secret);
    let (recovery_id, compact) = sig.serialize_compact();
    let mut bytes = compact.to_vec();
    bytes.push(recovery_id.to_i32() as u8);
    bytes
}

fn main() {
    let secp = Secp256k1::new();

    // === 1. recipient 生成密钥对 ===
    let (recipient_secret, recipient_tagged) = make_keypair();
    let recipient_addr = derive_address(&recipient_tagged);

    // === 2. 生成 5 个桥验证器密钥对 ===
    let validator_keys: Vec<(secp256k1::SecretKey, TaggedPubkey)> = (0..5)
        .map(|_| make_keypair())
        .collect();

    // === 3. 注册 BridgeValidatorSlot（5 个验证器，quorum=4）===
    let validator_set: BTreeSet<TaggedPubkey> = validator_keys
        .iter().map(|(_, t)| t.clone()).collect();
    let slot = BridgeValidatorSlot::new(0xAAAA, validator_set);
    let mut registry = BridgeRegistry::new();
    registry.register_slot(slot);

    // === 4. 构造 BridgeDeposit ===
    let deposit = BridgeDeposit {
        nonce: 1,
        source_chain_id: 0xAAAA,
        dest_chain_id: DEFAULT_CHAIN_ID,
        asset: [0xAB; 32],
        amount: 1000,
        recipient: recipient_addr,
        source_tx_hash: [0xCD; 32],
    };
    let msg_hash = deposit.message_hash();

    // === 5. recipient 对 deposit 签名（SEC2-M1 防抢跑）===
    let recipient_sig = sign(&secp, &recipient_secret, &msg_hash);

    // === 6. 桥验证器签名（4 个 = quorum）===
    let validator_sigs: Vec<BridgeValidatorSig> = validator_keys.iter().take(4)
        .map(|(s, t)| BridgeValidatorSig {
            validator: t.clone(),
            signature: sign(&secp, s, &msg_hash),
        })
        .collect();

    // === 7. 构造 BridgeVerifyTx ===
    let tx = BridgeVerifyTx {
        deposit,
        validator_signatures: validator_sigs,
        recipient_sig,
        recipient_pubkey: recipient_tagged,
        preferred_relayer: None, // 可选：Some(relayer_tagged)
    };

    // === 8. 协议层调用 bridge_verify ===
    let outcome = bridge_verify(&mut registry, &tx, DEFAULT_CHAIN_ID, true)
        .expect("bridge_verify 应成功");

    assert_eq!(outcome.deposit.amount, 1000);
    assert_eq!(outcome.recipient, recipient_addr);

    // === 9. 重复提交被拒绝（nonce 已消费）===
    let replay = bridge_verify(&mut registry, &tx, DEFAULT_CHAIN_ID, true);
    assert!(matches!(replay, Err(PokerL1Error::BridgeNonceConsumed(1))));
}
```

### 9.2 Burn & 提现示例

```rust
use poker_l1::bridge::{burn_on_source, BridgeRegistry, BurnProof};
use poker_l1::DEFAULT_CHAIN_ID;

fn withdraw_via_burn() {
    let mut registry = BridgeRegistry::new();

    let burn = BurnProof {
        burn_nonce: 1,
        source_chain_id: 0xAAAA,
        dest_chain_id: DEFAULT_CHAIN_ID,
        asset: [0xAB; 32],
        amount: 500,
        recipient: [0x02; 20],
        burn_tx_hash: [0xEF; 32],
    };

    // poker_l1 侧标记 burn_nonce 已消费
    burn_on_source(&mut registry, &burn, DEFAULT_CHAIN_ID)
        .expect("burn_on_source 应成功");

    // 重复 burn 被拒绝
    let replay = burn_on_source(&mut registry, &burn, DEFAULT_CHAIN_ID);
    assert!(matches!(replay, Err(PokerL1Error::BurnProofInvalid(_))));

    // 将 BurnProof 提交至源链以解锁原始资产（源链侧逻辑由源链桥合约实现）
}
```

### 9.3 合约调用拒绝示例

```rust
use poker_l1::bridge::{bridge_verify, BridgeRegistry, BridgeVerifyTx};
use poker_l1::error::PokerL1Error;
use poker_l1::DEFAULT_CHAIN_ID;

fn contract_call_rejected(tx: &BridgeVerifyTx) {
    let mut registry = BridgeRegistry::new();
    // is_protocol_caller = false → 拒绝
    let result = bridge_verify(&mut registry, tx, DEFAULT_CHAIN_ID, false);
    assert!(matches!(result, Err(PokerL1Error::BridgeVerifyNotAuthorized)));
}
```

### 9.4 桥验证器集动态变更示例

```rust
use poker_l1::bridge::{BridgeRegistry, BridgeValidatorSlot};
use std::collections::BTreeSet;

fn rotate_validators(
    registry: &mut BridgeRegistry,
    source_chain_id: u64,
    added: impl IntoIterator<Item = TaggedPubkey>,
    removed: impl IntoIterator<Item = TaggedPubkey>,
) {
    let existing = registry.slot(source_chain_id)
        .map(|s| s.validators.clone())
        .unwrap_or_default();

    let mut new_set = existing;
    for v in added { new_set.insert(v); }
    for v in removed { new_set.remove(&v); }

    // 重建 slot —— quorum 会自动按 ceil(n * 2 / 3) 重算
    let new_slot = BridgeValidatorSlot::new(source_chain_id, new_set);
    registry.register_slot(new_slot);
}
```

---

## 附录 A：源文件索引

| 模块 | 文件路径 |
|------|---------|
| 桥核心实现 | `poker_l1/src/bridge/mod.rs` |
| 错误定义 | `poker_l1/src/error.rs`（Phase 6: 跨链桥，第 541-559 行） |
| 测试辅助 | `poker_l1/tests/bridge_helpers.rs` |
| 签名验证 | `poker_l1/src/signature/unified.rs`（`verify_signature`） |
| 地址派生 | `poker_l1/src/account.rs`（`derive_address`） |
| TaggedPubkey | `poker_l1/src/signature.rs` |

## 附录 B：常量速查

| 常量 | 值 | 含义 |
|------|-----|------|
| `BRIDGE_SIG_DOMAIN` | `0x42` ('B') | 桥签名域分隔前缀 |
| `BURN_PROOF_DOMAIN` | `0x62` ('b') | Burn proof 域分隔前缀 |
| `DEFAULT_CHAIN_ID` | （见 `poker_l1/src/lib.rs`） | poker_l1 默认 chain_id |
| quorum 公式 | `ceil(n * 2 / 3)` | 桥验证器 quorum |

## 附录 C：相关 SubTask 索引

| SubTask | 描述 | 实现位置 |
|---------|------|---------|
| 34.1 | `BridgeHook` trait + `bridge_verify` syscall 接口 | `bridge/mod.rs:236-255` |
| 34.2 | 协议层调用强制（合约直连返回 `BridgeVerifyNotAuthorized`） | `bridge/mod.rs:340-342, 488-490` |
| 34.3 | 签名绑定 `(nonce, source_chain_id, dest_chain_id, asset, amount, recipient, source_tx_hash)` + recipient 签名 + preferred_relayer | `bridge/mod.rs:56-119, 333-409` |
| 34.4 | burn-on-source + burn proof | `bridge/mod.rs:130-171, 439-464` |
| 34.5 | 桥验证器插槽注册 | `bridge/mod.rs:178-215, 260-309` |
