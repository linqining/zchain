# 共识硬化六项 — 实施前确认清单

> 对应优先级列表 #1–#5、#8、#9。每项含：**现状结论 / 代码位置 / 必须决策的点 / 需要你拍板的选项**。
> 探查已完成（file:line 精确到函数签名），未做任何代码改动。

---

## ⚠️ 总体修正：6 项的实际工作量与初版清单出入很大

| 项 | 清单原以为 | 探查实情 | 实际工作量 |
|---|---|---|---|
| #1 共识签名验证 | 三条路径全缺 | **vertex 已接通真验签**；commit cert 验签函数已写好（未调用）；仅 slashing 路径真缺，且 commit-cert-equivocation 连签名字段都没有 | **小（中）** |
| #2 ECVRF | 替换 stub | 验证器 trait+stub 在；**prover 端完全不存在**；**无任何生产调用点**；需新增 ECVRF crate | **中** |
| #3 多签闭环 | 改 quorum 参数 | 架构性问题：validator loop 的 Dag 与 P2P 隔离、无投票 gossip、无 genesis validator set CLI 配置 | **大** |
| #8 AccountStore | "一行"持久化 | 确为机械改动，但需选 cache 策略 + 处理 executor 的 `&mut` 签名 | **小** |
| #4/#5 代币+奖励 | 接线 | **几乎全是绿地设计**：无代币、无 mint、无奖励、gas 被烧毁、stake 不入账 | **大（需设计）** |
| #9 Bridge | 接线 | 验证逻辑完整；**铸币原语不存在**；需 precompile + 铸币 + BridgeRegistry 生命周期 | **中** |

---

# 缺口 #1：接入共识签名验证

## 现状分路径（关键修正）

### 路径 A — Vertex 作者签名 ✅ 已接通（无需改动）
- `poker_l1/src/node/mod.rs:628-633` `validate_vertex` 已调用真 `verify_signature(&vertex.author_pubkey, &vertex.author_sig, &signing_hash)`。
- `vertex.signing_hash(chain_id)` = `blake2b(chain_id||epoch||round||author_pubkey||vertex_hash||parent_hashes)`。
- **此项零工作量。**（之前报告说该路径 stub，探查推翻了该判断）

### 路径 B — Commit Certificate 多签 ⚠️ 函数已写好但未调用
- 验签函数**已存在**：`poker_l1/src/consensus/cert_verification.rs:46` `verify_commit_certificate_signatures(cert, chain_id, validators: &[ValidatorEntry], verify_fn)`，含 bitmap→index 映射、去重、quorum、逐签名验，**已用真实 secp256k1 端到端测试过**（`:206`）。
- 生产路径只调用了**只数签名个数**的 `bullshark.rs:350 validate_commit_certificate_quorum`（注释明说"实际签名验证由 Task 10 实现"）。
- `DagCommitCertificate`（`consensus/mod.rs:210`）：`signature_list: Vec<Vec<u8>>`（每条 65B r||s||v）+ `signer_bitmap: Vec<u8>`（bit i = validators[i]）。签名对象 = `cert.signing_hash(chain_id)`（域 `0x43`，`mod.rs:114`）。
- **数据可用性**：validators[i].pubkey 在 `ValidatorSet.validators`（`validator_set.rs:306`，node 持有 `Mutex`），chain_id 在 `NodeConfig.chain_id`（`node/mod.rs:117`）——**调用点全有，直接接入即可**。

### 路径 C — Slashing 证据 ❌ 真缺（且 schema 不全）
- `VertexEquivocationEvidence`（`slashing.rs:378`）：有 `author`、`signature_1/2`，**但没有**可重算的签名对象——只存了 `vertex_hash_1/2`（32B），而 vertex 的 signing_hash 还需 chain_id + 完整 vertex 字段（tx_list、parent_hashes）。`validate()`（`:398`）只查非空。
- `CommitCertEquivocationEvidence`（`slashing.rs:421`）：**连 author 和 signature 字段都没有**，只有 `cert_hash_1/2`。生产构造点 `bullshark.rs:492` 当前不带签名。

## 需要你决策的点

**Q1（路径 B 接入位置）**：commit cert 验签应接入哪个"接受 cert/finalize"的生产点？
- 选项：① 区块 import 校验（`node/mod.rs validate_block`）；② 出块时自检（`build_block_from_vertex`）；③ 两者都加。
- 推荐 ③（出块方自检 + 收块方校验，纵深防御）。

**Q2（路径 C 签名对象来源）**：slashing 证据如何携带可验签名对象？三选一：
- ① 证据结构新增 `chain_id` + 两个完整 `DagVertex`（重，但最严谨）
- ② 证据结构新增 `chain_id` + 两个预算好的 `[u8;32]` signing_hash（轻，但验证方需信任提交方算的 hash）
- ③ 证据新增 `chain_id` + 足以重算 signing_hash 的最小字段
- **推荐 ①**：slashing 是低频高敏感操作，重算最安全。

**Q3（路径 C-commit schema 扩展）**：是否同意给 `CommitCertEquivocationEvidence` 增加 `author: TaggedPubkey` + `signature_1/2` + 两个 cert（或 signing_hash）字段？这是破坏性 schema 变更（影响 borsh/serde、测试、`bullshark.rs:492` 构造点）。

---

# 缺口 #2：实现真实 ECVRF-secp256k1

## 现状
- 验证器 trait `VrfVerifier`（`validator_set.rs:139`）：`verify(vrf_pubkey[33], input[32], proof: &VrfProof) -> PokerL1Result<[u8;32]>`。input = `blake2b(0x56||chain_id||epoch||prev_randomness)`，输出成为新 `epoch_randomness`。
- `VrfProof`（`:83`）：`gamma[33] || c[32] || s[32]`（97B），常量齐备。
- `StubVrfVerifier`（`:163`，cfg-gated 到 test/test-helpers）直接返回 input 当输出。
- verifier **不存于 ValidatorSet**，按 `&dyn VrfVerifier` 逐调用注入 `submit_epoch_vrf_proof`（`:507`）。

## 关键发现（需你确认方向）
- **❗ prover 端完全不存在**：全仓库无任何 VRF proof 生成代码（无 `prove_vrf`/`VrfProver`）。要做真 VRF，必须同时实现**prover + verifier**两半。
- **❗ 无任何生产调用点**：`submit_epoch_vrf_proof` 只被 2 个 `#[test]` 调用，epoch 转换 / 出块流程从不调用它。**换真 verifier 不会破坏任何运行路径**（但意味着"接入 VRF 到共识时序"本身也是未完成的子任务）。
- VRF 输出消费契约（`assigned_validator_for_game`，`:554`）：输出再经 `blake2b(game_id||epoch||epoch_randomness)` → 取前 8B `% active_count`（**非按 stake 加权**）。真 verifier 输出必须均匀分布 32B。
- **依赖**：当前无 ECVRF crate。`secp256k1 0.29`（已有）的 FFI **不暴露通用标量乘法/任意点运算**，不足以单独实现 ECVRF 的 hash-to-curve / hash_points。

## 需要你决策的点

**Q4（crate 选型）**：用哪个 ECVRF 实现？
- ① 加 `ecvrf` crate（crates.io 有 secp256k1-SHA256 变体）—— 最快
- ② 加 `vrf` crate（模块注释 `validator_set.rs:22` 提到的）
- ③ 自行基于 `secp256k1`+`ff`/`group` 实现（最重，但 secp256k1 群运算仍缺，可能要引 `secp256k1` 之上的纯 Rust 椭圆曲线库如 `k256`）
- **推荐 ①**，除非有审计/依赖洁癖要求。

**Q5（prover 的密钥来源）**：VRF 私钥从哪来？
- ① 复用 validator 的 secp256k1 ECDSA 私钥（同钥双用，简单但耦合）
- ② 独立 VRF 密钥对（更规范，`ValidatorEntry` 已有 `vrf_pubkey` 字段——需确认私钥如何配置/启动加载）
- **需要你确认 ValidatorEntry.vrf_pubkey 当前是否被填充、对应私钥的 CLI/env 入口**。

**Q6（接入共识时序，可选/后续）**：真 VRF 做完后，是否本次就把 `submit_epoch_vrf_proof` 接入 epoch 转换（`Node::advance_epoch` / `validator_set.rs:393`）？还是本次只做"可用的真 verifier/prover + 单元测试"，时序接入留作 #3 多签闭环的一部分？

---

# 缺口 #3：跑通多 validator 2/3 多签闭环

## 现状（这是 6 项中工作量最大的，架构性问题）
- validator loop（`src/main.rs:1120 run_validator_loop`）用 `detect_commit_leader(&dag, &prev_hash, 1)`——`1` 是 validator_count，`required_quorum(1)=1`，自引用即满足。注释 `:1118` 明说"quorum(1)"。
- commit cert **自签单签**：`build_block_from_vertex`（`main.rs:1129-1151`）用节点自己的 key 签，`signature_list: vec![cert_sig]`、`signer_bitmap: vec![0x01]`。**现成的 `bullshark.rs:433 assemble_commit_certificate` 从未被调用**。
- **❗ P2P 收到的 vertex 不进 validator loop 的 Dag**：`handle_p2p_connection`（`main.rs:861`）把 peer vertex 写入 `node.vertex_store`，但 loop 的 `Arc<Mutex<Dag>>`（`:417`）是私有的、只收自己的 vertex。→ `detect_commit_leader` 永远只能看到自己的 vertex，**永远无法凑到 2/3**。
- **❗ 完全没有投票/签名 gossip**：`NetworkMessage`（`network/mod.rs:517`）无 vote 变体；`GossipTopic`（`:504`）无 vote topic；无投票累加器。
- **❗ 无 genesis validator set CLI 配置**：`NodeConfig.genesis_validators`（`node/mod.rs:131`）存在但所有构造器都置空，`main.rs` 从不填充。没有它，所有节点对 validator 排序（signer_bitmap 的 index 基准 `active_validator_pubkeys_sorted()`）无法达成一致。
- 好消息：P2P 基础设施在——`--peer` 出站连接（`main.rs:241,367`）、入站 accept（`:386`）、`TcpTransport`（`:607`）；`detect_commit_leader`/`assemble_commit_certificate`/`validate_commit_certificate_quorum` 逻辑都正确。

## 需要你决策的点

**Q7（实现深度）**：本次要做到哪一层？
- ① **完整 4N BFT 闭环**：新建 vote gossip + Dag 共享 + genesis set CLI + 替换自签——工作量大
- ② **"多进程能凑齐 2/3"最小可用**：只做 Dag 共享 + vote gossip + genesis set CLI，commit cert 用聚合签名（暂不做 leader 抗拜占庭的完整 Bullshark 选举优化）
- ③ **仅去掉 quorum=1 demo**：改 `detect_commit_leader` 的 count 参数 + Dag 共享，但 cert 仍单签（仅"形式上"多 validator，安全性未达标）——**不推荐**，等于没解决

**Q8（vote gossip 协议设计）**：
- ① 显式 `CommitVote { epoch, commit_round, vertex_hash_list, signer_pubkey, signature }` 网络消息（清晰、易调试）
- ② 复用 vertex 的 parent_hashes 作为"隐式投票"（更贴合 Bullshark 原论文，但需在 detect_commit 时一并收集这些 vertex 的 author_sig 作为 cert 签名）
- **推荐 ②**（Bullshark 原生做法，少一层网络消息），但需确认 `assemble_commit_certificate` 能从 commit 的 referencing vertices 提取 author 签名。

**Q9（genesis validator set 配置格式）**：
- ① CLI `--genesis-validators <file>`（JSON/TOML：pubkey + vrf_pubkey + stake 列表）
- ② 硬编码到 chain_id 派生
- ③ 首个 validator 启动时注册、其余从链上同步
- **推荐 ①**。

**Q10（测试方式）**：多进程集成测试需要脚本起 N 个进程（`scripts/`），还是单进程内多 `Node` 实例 + `InMemoryTransport` 做集成测试？后者快但 `main.rs` 当前不支持多 Node。

---

# 缺口 #8：AccountStore 落 RocksDB

## 现状（确为机械改动，最小）
- `AccountStore`（`account/mod.rs:258`）= 裸 `HashMap<Address, Account>`，`Account` 已 derive `BorshSerialize/Deserialize` + `Serialize/Deserialize`（roundtrip 测试通过）。
- Node 持有 `Mutex<AccountStore>`（`node/mod.rs:310`），`Node::open`（`:378`）始终 `AccountStore::new()`——**从不传路径**，重启即丢。
- 对比模板 `BlockStore`/`ObjectDb`：`Arc<DB>` + `ColumnFamilyDescriptor::new("accounts", ...)` + `borsh::to_vec/from_slice` + `PokerL1Error::Rocksdb/Serialization`，外加 `open_inmemory()`（temp dir）。**可直接复制**。
- 写点：executor 的 `apply_public_tx`（`executor/mod.rs:658`）走 `account_store.get_mut` → `Account::debit`+`increment_nonce`。

## 需要你决策的点

**Q11（cache 策略）**：
- ① 纯 RocksDB（像 BlockStore，无内存 cache）——简单，但每次 get_mut 都一次 DB 读
- ② RocksDB + 内存 HashMap cache（像 ObjectDb 为 SMT 那样）——快，但需维护一致性 + 启动全量加载
- **推荐 ①**（账户无 Merkle 树需求，纯 DB 足够，避免双写一致性负担）。

**Q12（`&mut AccountStore` 签名影响）**：
- 若选纯 RocksDB，`AccountStore` 自身 `Sync`（经 `Arc<DB>`），可去掉 Node 上的 `Mutex`。但 executor 当前签名是 `&mut AccountStore`（`execute_block`），去 Mutex 后需把 `&mut` 改成 `&self` + 内部 `put_cf`。
- 选项：① 去掉 Mutex，executor 改 `&self`（侵入 executor 签名，但更干净）；② 保留 Mutex（最小改动，但 DB 写在持锁内）。
- **推荐 ②（保留 Mutex）**作为本次最小改动；executor 签名重构留作后续。

**Q13（genesis 账户分配）**：新持久化 store 启动为空。是否本次顺带加一个 genesis-alloc 加载（与 #4 代币发行耦合）？还是本次只做"持久化壳"，账户仍由运行时 `put_account` 创建？
- **推荐本次只做持久化壳**，genesis 分配随 #4 一起做。

---

# 缺口 #4 / #5：定义原生代币与奖励分发

## 现状（这是 6 项中设计自由度最大的，几乎全是绿地）
- `Account.balance: u64` 语义仅为"gas 支付单位"，**无代币名/符号/精度/总量**。
- **无 mint**：grep `mint/supply/treasury/coinbase/inflation` 全空。唯一"burn"是跨链桥的（烧 wrapped 对象，无关）。
- **gas 被烧毁**：`apply_public_tx` 调 `account.debit(gas_used)`，**不计入任何 proposer/treasury**，从（未追踪的）总供应中消失。
- **无出块奖励**：`BlockExecutionOutcome` 只有 `total_gas_used`，无 reward 字段。
- **stake 不入账**：`ValidatorEntry.stake`（`validator_set.rs:247`）、`designated_operator_bond_amount` 等都是裸 u64，**无托管、不与 Account.balance 结算**；slashing 只减 stake 字段、不 credit 任何账户、`challenge_reward_ratio` 无发放实现。
- **无原生转账 tx**：Transaction 全是对象导向（inputs/outputs/contract_call），无原生 balance 转移；VM 也无触碰 `Account.balance` 的 syscall。
- governance 有经济参数（slash_percentage、forfeit_ratio 等）但全是纯比例，无代币单位。

## 需要你决策的点（这些是设计题，必须先定才能编码）

**Q14（代币身份）**：名称、符号、decimals、初始/总量上限？balance 仍用 `Account.balance: u64`（最小原子单位）还是要单独账本？

**Q15（发行与 genesis 分配）**：
- ① 固定总量，genesis 一次性 mint 给初始持有者
- ② 通胀（随出块增发奖励）
- ③ 混合（genesis + 受控通胀上限）
- genesis 分配如何加载（文件？与 #8 的 genesis-alloc 合一？）

**Q16（gas 去向）**——当前烧毁，需选：
- ① 保持烧毁（通缩，最简单，无需改 executor 结构）
- ② 奖励给出块 proposer（需在 executor 引入"proposer Account"概念，`ExecutionEnvironment` 当前无此字段）
- ③ 部分进国库 + 部分 proposer
- **影响范围**：executor `apply_public_tx`（`:658`）+ block 提交逻辑。

**Q17（出块奖励）**：金额、衰减 schedule、发放对象（proposer / 全体 validator 按 stake 比例 / 国库）？在哪一步应用（每个 block 追加 system/coinbase tx，还是 `execute_block` 内联）？

**Q18（原生转账 tx）**：
- ① 新增 `Transaction` 变体 / 新 `TxLane::Transfer`（破坏 signing_hash，共识相关）
- ② 用一个系统预编译转账（读/写 `Account.balance`，需新增 syscall 或预编译特权）
- **注意**：这两条都触及签名域与 VM 能力边界。

**Q19（staking/质押结算，scope 取舍）**：把 `ValidatorEntry.stake`/bond 真正接到 AccountStore 托管、slashing 真扣账 + 奖励真发放——这是个大子系统。
- 选项：① 本次完整做；② 本次只做代币+gas 去向+奖励，staking 结算留后续。
- **推荐 ②**（先把基础代币循环跑通，staking 结算依赖前述且涉及 slashing/#1）。

**Q20（范围确认）**：鉴于 #4/#5 是大设计，是否同意**拆成两个里程碑**：M1 = 代币定义 + genesis 分配 + gas 去向决策 + 原生转账；M2 = 出块奖励 + staking 结算？还是一次性全做？

---

# 缺口 #9：接线 Bridge 执行路径

## 现状
- 验证逻辑完整且自测：`bridge_verify`（`bridge/mod.rs:347`）返回 `BridgeVerifyOutcome{deposit, recipient, preferred_relayer}`；`burn_on_source`（`:451`）；`BridgeRegistry`（`:273`）有 nonce 去重；2/3+1 quorum；真实 recipient 签名验证。
- **❗ 完全无外部调用者**（仅 bridge/mod.rs + error.rs 引用）。
- **❗ 铸币原语不存在**：`bridge_verify` 文档（`:339`）说"返回后由协议层执行铸造"，但**铸币实现为零**——无 wrapped 对象类型、无 mint primitive。
- **❗ BridgeRegistry 无生命周期**：未进 `ExecutionEnvironment`（`executor/mod.rs:60`），未持久化，无法跨 tx 保留 nonce 状态。
- dispatch 机制明确：executor 在 `:288` fork——precompile（`registry.execute`）或 rBPF。**无 bridge selector / bridge 合约 id**。
- `BridgeHook` trait（`:244`）声明但从未实现、BridgeRegistry 也不存它——是死代码（实际工作由自由函数 `bridge_verify` 完成）。
- `vm/syscalls.rs:1190` 注册了 11 个 syscall，**无 bridge**；`bridge_verify_contract_call_denied()`（`:500`）是为 syscall 拒绝路径预置的桩。

## 需要你决策的点

**Q21（接入方式）**：
- ① 新建 `BridgePrecompile` impl `Precompile`（`vm/precompile.rs:42`），保留 id `0xFF…03`，`call()` 内调 `bridge_verify`——**推荐**（与现有 GamePrecompile 一致）
- ② 新增 `bridge_verify` syscall（与模块 SubTask 34.1 注释吻合）
- 推荐 ①（precompile 路径已是协议层，`is_protocol_caller=true` 名正言顺）。

**Q22（铸币语义 — 最大缺口）**：deposit 验证通过后铸造什么？
- ① 铸造 wrapped **Object**（新 `Ownership` 变体或 typed data 携带 `(asset, amount)`）给 recipient
- ② credit recipient 的 `Account.balance`（需先有 #4 代币，且 wrapped 资产是否等同原生代币？通常**不等同**——应是独立资产）
- ③ 独立的 wrapped-asset 账本（per-asset 余额表）
- **依赖**：② 耦合 #4；① 最独立但需定义 wrapped 对象标准。
- **需要你定桥接的资产模型**。

**Q23（mint primitive 落地）**：选 ① 的话，铸币走 `apply_tx_outputs`（`executor/mod.rs:482`，但强制 `creator==caller`，recipient 恰是 caller/SEC2-M1 可行）还是 precompile 内直接 `Object::new`？需确认 wrapped 对象的 `id.creator_address`、`object_type`、与裁剪/索引器的交互。

**Q24（BridgeRegistry 生命周期 + 持久化）**：
- ① 放进 `ExecutionEnvironment`（`executor/mod.rs:60`），内存态 + 进程生命周期（重启丢 nonce 状态 → 重复铸币风险❗）
- ② 持久化到 RocksDB（nonce 去重必须持久，否则重启重放铸币）——**强烈建议**，但需新 store
- 与 `storage/pruning.rs:451` 的 `BridgeOperation` 永久保留项对齐。
- **nonce 持久化是安全刚需**，请确认本次一并做。

**Q25（反向路径 burn）**：`burn_on_source` 对称接入（先烧 wrapped 对象再生成 BurnProof）是否本次做，还是只做单向 deposit→mint？

---

# 建议的实施顺序与依赖

```
#8 AccountStore 持久化（无依赖，机械，先做暖身）
   │
   ├─→ #4/#5 代币+奖励（依赖 #8：reward 要 credit 持久账户）
   │       │
   │       └─→ #9 Bridge（wrapped 资产若用原生 balance 则依赖 #4；nonce 持久化用 #8 模式）
   │
#1 共识签名验证（独立，路径 B 即接即用；路径 C 需 schema）
   │
   └─→ #3 多签闭环（依赖 #1：commit cert 验签必须先就位，否则多签闭环无意义）
            │
            └─→ #2 ECVRF（leader 随机性，理想上在 #3 之后接入时序）
```

**最低风险推进**：#8 → #1(路径B) → #4(M1) → #9 → #3 → #2 → #1(路径C) → #5(M2)
（#1路径B和#8无相互依赖，可并行；#3 是最大工程，建议放代币/桥之后）

---

# 需要你离开前回复的最小决策集

若你希望我离开期间自主推进，**至少**为以下打 ★ 的问题给出方向（其余我按"推荐"项执行）：

- ★ Q3 slashing schema 破坏性变更是否同意
- ★ Q4 ECVRF crate 选型
- ★ Q7 #3 实现深度（完整闭环 / 最小可用 / 仅去 demo）
- ★ Q15 代币发行模型（固定 / 通胀 / 混合）
- ★ Q16 gas 去向（烧毁 / 奖励 proposer / 拆分）
- ★ Q22 Bridge 铸币资产模型（wrapped Object / 原生 balance / 独立账本）
- ★ Q24 Bridge nonce 持久化是否本次做（安全相关，强烈建议是）
- ★ Q20 #4/#5 是否拆里程碑
- Q25 Bridge 单向/双向

你也可以直接说"全部按推荐执行"，我会按上表推荐项 + 上述顺序推进，遇到不可逆决策（schema 变更、新依赖）时暂停留痕。
