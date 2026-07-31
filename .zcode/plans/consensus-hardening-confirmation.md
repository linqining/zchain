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

---

# 实施进度日志（决策已确认后开始执行）

## ✅ 已完成

### #8 AccountStore 落 RocksDB 持久化 — DONE
- `poker_l1/src/account/mod.rs`：`AccountStore` 改为混合模型（内存 HashMap 权威态 + 可选 `Arc<DB>` 后端）。新增 `open(path)` / `open_inmemory()` / `flush(addr)` / `persist(addr)`；`create`/`credit` 变更后自动落盘；`get_mut` 路径由调用方显式 `flush`。
- `poker_l1/src/node/mod.rs:364` `Node::open` 改用 `AccountStore::open(data_dir/accounts)`（重启不再丢账户）。
- `poker_l1/src/executor/mod.rs`：串行(`:753`)与并行(`:656`)两条 gas 结算路径在变更后显式 `flush(&caller)`。
- 新增 3 个持久化测试（重启后余额/nonce 保留 + 内存模式 no-op）。**1587 测试全通过**。

### #1-路径B commit cert 验签 — DONE（发现已就位，无需新代码）
- **关键修正**：探查发现 `Node::validate_block`（`node/mod.rs:701`）**已经**调用 `block/validator.rs:444 validate_commit_certificate_signatures`，后者对每个签名调用真 `verify_signature`（`validator.rs:482`）。`put_block`（`:665`）→ `validate_block` → 该函数。**导入路径已完整验签。**
- 生产出块路径（`build_block_from_vertex`）自签 cert，无需自验。
- 结论：缺口 #1 的 commit-cert 部分实际**不存在**——之前报告判断有误。唯一真缺的是 slashing 路径（#1-路径C，留后）。

## 🔄 进行中 / 待设计

### #4-M1 代币 — 暂停，记录设计规范（共识敏感，需谨慎）
**为何暂停**：M1 的"gas→proposer"涉及 `ExecutionEnvironment` 增加 proposer 字段 + 出块/验块双方都要传入 proposer，属共识面变更；"原生转账"需扩 `Precompile` trait 签名（当前 `execute` 只收 `object_db` 不收 `AccountStore`）。这两项都跨多模块且影响 state_root 可重现性，不宜在无法跑多节点回归时盲改。

**已确定的设计（按你的决策）**：
- 代币模型：**混合**（Q15）— genesis 固定初始分配 + 受控通胀上限（出块奖励，M2）。
- gas 去向：**奖励 proposer**（Q16）— 不再烧毁。
- 拆分：M1（代币定义+genesis分配+gas→proposer+原生转账）/ M2（出块奖励+staking 结算）（Q20 同意）。

**M1 实施规范（待恢复时执行）**：
1. **原生转账**：在 `vm/contracts/` 新增 `transfer_precompile.rs`，id `0xFF…04`。
   - **障碍**：`Precompile::execute` 签名（`vm/precompile.rs:42`）当前只收 `&mut impl ObjectBackend`，无 `AccountStore`。需把 `&mut AccountStore` 加入 trait 签名（破坏性，影响所有现有 Precompile 实现：GamePrecompile、TexasPokerPrecompile）。
   - 备选（更小侵入）：在 `executor/mod.rs:288` dispatch 前，对"系统 transfer contract_id"做特判，直接在 executor 内操作 `account_store`（caller debit amount + recipient credit），绕过 Precompile trait。**推荐备选**。
2. **gas→proposer**：
   - `ExecutionEnvironment`（`executor/mod.rs:56`）增 `proposer: Option<TaggedPubkey>` 字段（运行时，**非** BlockHeader 字段，避免改 block_hash）。
   - 出块方（`main.rs build_block_from_vertex`）传入自己的 pubkey；验块方从 cert 的 leader signer 派生 proposer。
   - `apply_public_tx`（`account/mod.rs:231`）扣的 gas 不再凭空消失：在 block 结束时把 `total_gas_used` 信用给 proposer（`AccountStore::credit(proposer_addr, total_gas_used)`）。注意 state_root 可重现性：proposer 信用必须在**确定性位置**（block 末尾、所有 tx 之后）执行，使出块/验块双方 state_root 一致。
3. **genesis 分配**：`Node::open` 后从 `genesis_alloc` 配置（文件，与 #3 的 genesis validator set 文件合并）mint 初始余额到初始账户。复用 #8 的持久化 store。

### 接下来转向 #2 ECVRF（自包含、无共识面权衡、解锁 #3）

## ✅ 已完成（续）

### #2 ECVRF-secp256k1-SHA256-TAI prover + verifier — DONE
- `poker_l1/Cargo.toml`：新增 `vrf = "0.2.5"` + `openssl = { features=["vendored"] }`。
  - **关键**：构建机系统 OpenSSL 仅 x86_64（本机是 arm64），vendored 从源码编译 OpenSSL 保证可复现构建（首次约 75s，之后缓存）。
- `poker_l1/src/consensus/ecvrf.rs`（新模块）：`Secp256k1VrfVerifier`（impl `VrfVerifier`）+ `Secp256k1VrfProver`（`prove()` + `derive_public_key()`）。基于 `vrf::openssl::ECVRF` 的 `SECP256K1_SHA256_TAI`（draft-irtf-cfrg-vrf-05）。
- **proof 布局修正**：`VrfProof` 从旧 `gamma[33]||c[32]||s[32]`=97B 改为规范 `gamma[33]||c[16]||s[32]`=81B（`c` 在 secp256k1-SHA256-TAI 中是 n/8=16 字节，非 32）。`VRF_PROOF_SIZE=81`。
- `error.rs`：`InvalidVrfProof` 改为带 `String` 上下文。
- 6 个新测试：prover↔verifier roundtrip（output 一致）、错误 pubkey 拒绝、错误 input 拒绝、81B 回归、不同 input 不同 output、与旧 placeholder 派生分离。**全 1593 测试通过，workspace 构建 OK。**
- **接入 epoch 时序留作 #3 的一部分**（Q6）：prover/verifier 已就绪且独立测试通过，但 `submit_epoch_vrf_proof` 仍未在生产 epoch 转换中调用（这与 #3 的多签闭环一起做）。

## 待办优先级重排
已完成 3 项（#8、#1-路径B、#2）。剩余按"独立性 + 低风险"排序：
1. **#1-路径C**（slashing 验签，Q3 已批准 schema 破坏性变更，独立，有限范围）
2. **#9**（Bridge 接线，依赖 #4 的代币模型若用原生 balance，但选了 wrapped Object 较独立）
3. **#3**（多签闭环，最大工程，依赖 #1+#2 都已就位）
4. **#4-M1**（代币，需共识面回归，已记规范）
5. **#5-M2**（出块奖励+staking，最后）

## ✅ 已完成（续 2）

### #1-路径C slashing 验签接入 — DONE
- **Q3 破坏性 schema 变更已落地**：
  - `VertexEquivocationEvidence`（`slashing.rs`）：从 `(epoch, round, author, vertex_hash_1/2, signature_1/2)` 改为 `(chain_id, epoch, round, author, vertex_1: DagVertex, vertex_2: DagVertex)`。`validate()` 现严格重算 `vertex.signing_hash(chain_id)` 并对两 author_sig 调真 `verify_signature`。
  - `CommitCertEquivocationEvidence`（`slashing.rs`）：从 `(epoch, commit_round, cert_hash_1/2)` 改为 `(chain_id, epoch, commit_round, author, signature_1/2, cert_1: DagCommitCertificate, cert_2: DagCommitCertificate)`。`validate()` 重算 cert signing_hash 并验双签。
  - `detect_commit_cert_equivocation`（`bullshark.rs`）：新增 `validators: &[ValidatorEntry]` 参数，从两 cert signer_bitmap 交集找双签 validator 构造完整证据。
- 新增真实 secp256k1 签名的测试辅助 + 重写全部 slashing 证据测试（双签通过、相同 vertex 拒绝、篡改签名拒绝、author 不符拒绝、cert 双签通过/相同/篡改）。
- **全 1595 测试通过，workspace 构建 OK。**

## 阶段性总结（你离开期间已交付 4 项）
| 项 | 状态 | 测试 |
|---|---|---|
| #8 AccountStore 持久化 | ✅ DONE | 3 新测试 + 全量 |
| #1-路径B commit cert 验签 | ✅ DONE（探查发现已就位） | 现有 |
| #2 ECVRF prover+verifier | ✅ DONE | 6 新测试 |
| #1-路径C slashing 验签 | ✅ DONE | 8 重写测试 |
| 全量回归 | ✅ 1595 passed | — |

**未开始（剩余 4 项）**：
- #9 Bridge：验证逻辑完整待接线，需 wrapped Object 模型 + nonce 持久化（Q22 wrapped Object，独立于 #4）。
- #3 多 validator BFT 闭环：最大工程（main.rs loop 重写 + vote gossip + genesis set CLI + VRF 时序接入）。#1+#2 已就位为其铺路。
- #4-M1 代币：已记规范，待共识面回归（gas→proposer 涉 ExecutionEnvironment/BlockHeader）。
- #5-M2 出块奖励+staking：最后。

## 继续推进 #9 Bridge（独立、Q22 wrapped Object 不依赖 #4）

# 剩余 4 项 — 详细实施规范（暂停待你回归）

> **为何在此暂停**：已交付 4 项（#8/#1B/#2/#1C，全 1595 测试通过）。剩余 4 项
> （#9/#3/#4-M1/#5-M2）**全部触及 state_root 可重现性或共识面**，在无法跑多节点
> 回归时盲改风险高。以下规范精确到 file:line / 函数签名 / schema，恢复时可直接落地。

---

## #9 Bridge 接线 — 实施规范（最独立，建议先做）

**目标**：把已完整测试的 `bridge_verify`（`bridge/mod.rs:347`）接通到执行路径，deposit 验证通过后铸造 wrapped Object 给 recipient，BridgeRegistry nonce 持久化。

### 9.1 wrapped-asset Object 模型（Q22）
新增常量 `pub const BRIDGE_WRAPPED_OBJECT_TYPE: &str = "bridge-wrapped-asset";`
wrapped Object 构造：
```
Object::new(
    id: ObjectID::new(recipient, creation_nonce),   // creator_address = recipient（SEC2-M1：recipient 是 caller）
    owner: Ownership::AddressOwned { owner: recipient },
    object_type: "bridge-wrapped-asset",
    data: borsh::to_vec(&WrappedAsset { source_chain_id, asset, amount })?,
    assigned_validator: None,
)
```
`WrappedAsset` 新 struct（`bridge/mod.rs`）：`{ source_chain_id: ChainId, asset: Hash, amount: u64 }`，derive Borsh。

### 9.2 铸币函数（新增）
`bridge/mod.rs` 新增：
```rust
pub fn mint_wrapped_object<B: ObjectBackend>(
    outcome: &BridgeVerifyOutcome,
    object_db: &mut B,
    creation_nonce: u64,
) -> PokerL1Result<ObjectID>
```
- 用 `outcome.deposit.{source_chain_id, asset, amount}` + `outcome.recipient` 构造 wrapped Object
- `object_db.create(&obj)` 落库（影响 state_root）
- 返回新 ObjectID

### 9.3 BridgeRegistry nonce 持久化（Q24，安全刚需）
新增 `poker_l1/src/storage/bridge_registry_store.rs`（仿 `AccountStore` 混合模型，缺口 #8 模板）：
- RocksDB CF `bridge_nonces`（key=`(chain_id_le || nonce_le)` → value=空）+ `bridge_burn_nonces`
- `BridgeRegistryStore::open(path)` / `open_inmemory()`
- 启动时全量加载到内存 `BridgeRegistry`（其 `consumed_nonces`/`consumed_burn_nonces`）
- `bridge_verify`/`burn_on_source` 成功后调用 `persist_nonce(chain_id, nonce)` 落盘

### 9.4 接入执行路径（方案A：executor 特判，最小侵入）
`executor/mod.rs:288` dispatch fork，在 precompile 分支前加 bridge 特判：
```rust
if call.contract_id == BRIDGE_PRECOMPILE_ID {
    let tx_bcs: BridgeVerifyTx = borsh::from_slice(&call.args)?;
    // registry 从 ExecutionEnvironment 注入（见 9.5）
    let outcome = bridge_verify(env.bridge_registry, &tx_bcs, env.chain_id, true)?;
    let obj_id = mint_wrapped_object(&outcome, object_db, /*creation_nonce*/)?;
    env.bridge_registry_store.persist_nonce(tx_bcs.deposit.source_chain_id, tx_bcs.deposit.nonce)?;
    all_created.push(obj_id);
    // 注意：gas 仍按 Public lane 计费（recipient 是 caller）
    return ...;
}
```
新增常量 `BRIDGE_PRECOMPILE_ID: ObjectID = 0xFF...03`（`vm/precompile.rs::reserved`）。

### 9.5 ExecutionEnvironment 扩展
`executor/mod.rs:56` ExecutionEnvironment 增字段：
- `bridge_registry: Option<Arc<Mutex<BridgeRegistry>>>`
- `bridge_registry_store: Option<Arc<BridgeRegistryStore>>`
出块方（`main.rs build_block_from_vertex`）与验块方（`node/mod.rs validate_block`）都注入（验块方用相同的持久化 store）。**state_root 可重现性**：wrapped Object 创建是确定性的（同 recipient + 同 creation_nonce → 同 ObjectID），故出块/验块 state_root 一致。

### 9.6 反向 burn（Q25 单向/双向 — 待你定）
若做双向：`burn_wrapped_object(object_id, object_db)` 销毁 wrapped Object + 生成 BurnProof → `burn_on_source`。本次可只做单向 deposit→mint（Q25 未明确，默认单向）。

### 9.7 测试
- 单元：`mint_wrapped_object` 创建正确 wrapped Object（type/owner/data）
- 集成：bridge_verify 通过 → mint → Object 落库 → state_root 变化；nonce 重启持久化（仿 #8 测试）

**工作量预估**：~300 行代码 + 持久化 store + 测试。

---

## #3 多 validator BFT 闭环 — 实施规范（最大工程）

**前置已就位**：#1（cert 验签）、#2（VRF）。

### 3.1 Dag 共享（关键 bug）
当前 `main.rs:417` 的 `Arc<Mutex<Dag>>` 私有于 validator 线程，`handle_p2p_connection`（`:861`）把 peer vertex 写 `node.vertex_store` 但不进这个 Dag。
**改法**：把 `Arc<Mutex<Dag>>` 提到 `run_node` 顶层，传入 `handle_p2p_connection`，peer `DagVertex` 消息同时 `dag.insert()` + `node.put_vertex()`。

### 3.2 vote gossip（Q8 选项②：复用 vertex 隐式投票，Bullshark 原生）
不加显式 `CommitVote` 消息。`detect_commit_leader`（`bullshark.rs:127`）已按 distinct author 计数 parent 引用。cert 签名从 commit 的 referencing vertices 的 `author_sig` 提取（每个 author 对自己 vertex 的签名即"投票"）。
**新增**：`assemble_commit_certificate`（`bullshark.rs:433`）改为从 referencing vertices 提取 `(author_idx, author_sig)` 填充 signature_list。需把 vertex 的 signing_hash 与 cert signing_hash 对齐——**注意：cert signing_hash 域(0x43) 与 vertex signing_hash 域不同**，故 vertex 的 author_sig **不能直接作为 cert 签名**。这迫使选 Q8 选项①（显式 CommitVote 消息）。

### 3.3 显式 CommitVote（修订：必须用选项①）
因 cert signing_hash 与 vertex signing_hash 域不同，validator 观察到 commit leader 后须单独对 `cert.signing_hash` 签名并 gossip：
- `network/mod.rs:517` NetworkMessage 新增 `CommitVote { epoch, commit_round, cert_signing_hash, signer_pubkey, signature }`
- `network/mod.rs:504` GossipTopic 新增 `CommitVote`
- `handle_p2p_connection` 新增 arm：收到 CommitVote 存入共享 `Arc<Mutex<HashMap<(epoch,commit_round), Vec<(pubkey,sig)>>>>`
- validator loop：检测到 leader → 签 `cert.signing_hash` → gossip CommitVote → 累加到 ≥2/3 → `assemble_commit_certificate` → 出块

### 3.4 validator_count 与 parent quorum
- `main.rs:1327` `detect_commit_leader(&dag, &prev_hash, 1)` → `detect_commit_leader(&dag, &prev_hash, node.active_validator_count())`
- `main.rs:1273` `validate_parents(1)` → `validate_parents(node.active_validator_count())`
- `build_block_from_vertex`（`:1142-1151`）自签单签 → 改用 `assemble_commit_certificate(collected_votes, validator_count)`

### 3.5 genesis validator set CLI（Q9 选项①）
- `run_node`（`main.rs:178-253`）新增 `--genesis-validators <file>`（JSON：`[{pubkey, vrf_pubkey, stake}]`）
- 填 `NodeConfig.genesis_validators`（`node/mod.rs:131`，当前所有构造器置空）
- 所有节点须用相同文件（signer_bitmap index 基准 = `active_validator_pubkeys_sorted()`）

### 3.6 VRF 时序接入（Q6）
`Node::advance_epoch`（`node/mod.rs:503`）/ epoch 转换处：proposer 用 `Secp256k1VrfProver` 生成 proof → gossip → `submit_epoch_vrf_proof(chain_id, proposer, proof, &Secp256k1VrfVerifier::new())`。

### 3.7 测试（Q10）
单进程内多 `Node` + 共享 `InMemoryTransport` 集成测试：3 validator，提交 tx → 各自产 vertex → 互收 → 检测 leader → 互投 CommitVote → 2/3 凑齐 → 出块 → 各方 validate_block 通过。

**工作量预估**：~600 行（main.rs loop 重写 + 网络消息 + CLI + 集成测试）。**风险最高**。

---

## #4-M1 代币（已记规范见上文 M1 段）/ #5-M2（最后）
保持已记规范。#4-M1 的 gas→proposer 需在 block 末尾确定性位置 credit proposer（保证 state_root 可重现）。

---

## 建议恢复顺序
1. **#9 Bridge**（独立，规范已就绪，~300 行）
2. **#3 多签闭环**（最大，但前置 #1/#2 已就位）
3. **#4-M1** → **#5-M2**

