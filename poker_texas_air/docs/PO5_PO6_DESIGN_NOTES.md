# P0-5 / P0-6 实现与剩余可信边界

> 本文区分已落地的 fail-closed/host 机制和仍需密码学或 AIR 重设计的部分。
> “测试通过”不等于递归聚合、Rust↔Lean 精化或完整下注状态机已经证明。

---

## P0-5:Aggregator 不验证任何子证明

本项拆分为两个不同的交付边界：
- **P05-H-core（Host O(N) verification）：✅ 已完成。** 完整 VM dispatch replay、
  逐 proof 原生验证、opaque receipt、连续性和显式 `ExpectedChainAnchor` 首尾/范围/
  调用 digest 校验均已实现。
- **P05-H-source（共识来源接入）：✅ 已闭合（inclusion-proof）。**
  `poker_texas_air::consensus_anchor::build_anchor_from_consensus` 把「已认证 `BlockHeader` +
  `DagCommitCertificate` + 每调用 SMT 包含证明」转换成 `ExpectedChainAnchor`，每步都做
  密码学校验：(1) cert 字段一致性（`validate_commit_certificate_fields`）+ 新增的
  `poker_l1::consensus::cert_verification::verify_commit_certificate_signatures`（≥ 2/3
  secp256k1 quorum 签名，镜像 `verify_light_client_header`）；(2) 单桌 `Object` snapshot
  用 `SparseMerkleTree::verify` 证明属于块的全局 `state_root`，从而锚定端点
  `pre/post_state_root = compute_state_root(table)`；(3) 每个 dispatch tx 用 SMT 包含证明
  认证属于 `public_tx_root`/`gameturn_tx_root`，digest 从 `{tx, header}` 独立重算。
  `proving_service::TexasPokerPlugin::verify_chain_against_consensus` 调
  `VerifiedChain::verify_against_anchor` 走该路径。
  **固有边界（文档化）**：共识层签名的 tx root 是 order-independent 的 SMT，**不**签名
  「某 table+hand 的有序调用序列」；调用顺序由 `hand_id`/`call_seq` 重建，线性顺序信任
  Bullshark projection 一致性。这不削弱每个 tx 都被 quorum 签名认证这一事实。
- **P05-R（Recursive/succinct aggregation）：❌ 未完成。** 当前递归后端不 sound，
  不存在可转移的单聚合 proof。

### 根因
`AggregatorAir` 是 descriptor-only PoC:
- 接口只接收 `ChildDescriptor`(`aggregator_air.rs:107`),仅含 `pre/post_state_root` + `call_seq` + `method_kind`,**不含 StarkProof**。
- `evaluate`(`aggregator_air.rs:175-256`)只约束链式连续性(`left.post_state_root == right.pre_state_root`)+ method_kind/call_seq 一致性,**零个约束触及 StarkProof/commitment/FRI**。
- 生产入口 `prove_aggregator`/`verify_aggregator` 已 fail-closed(`UntrustedAggregationDisabled`),仅 `*_unchecked_for_tests` 跑。

### 数据流问题
`ProvenTask` 仍只是 root/call_seq descriptor，不能作为子证明已验证的证据。
当前可信过渡路径已改为：Orchestrator 先用任务携带的完整
`DispatchContext + selector + raw_args` 重放公开 VM dispatch，要求完整 post table、
method input 与任务元数据逐字段一致；随后对每个 `MethodProof` 调用原生
Stwo verifier，成功后才签发字段私有的 `VerificationReceipt`，然后由
`VerifiedChainBuilder` 检查 table/hand/call_seq/完整 Poseidon252 root/version 连续性。
dispatch 调用摘要也被混入 method proof transcript。receipt 字段和链构造 API 已收窄为
crate-private，因此 descriptor 不能伪造 receipt；但外部仍可向 public Orchestrator 提交
任意自洽的离线 task，并获得“该转移经 VM replay + native verify”的 opaque receipt。

Mental Poker 方法的 AIR 仍未嵌入 DLEq/shuffle/reveal/reconstruct verifier AIR；
当前 host 路径依赖上述完整 VM replay 执行原生密码学验证。原有
`TableConfig.zk_skip_*` 运行时开关曾使默认桌台可跳过这一步；现已收窄为
`poker_l1` crate 自身 `cfg(test)` 单元测试专用。普通库、集成测试与生产
构建即使解析到旧的 skip 字段，`skip_*()` 也始终返回 false。这闭合了
host replay 的默认绕过，但不代替 recursive crypto verifier AIR。
此外，`leave_with_proof` 的退款已与 `leave_table` 对齐为 checked-u64：
refund 溢出或 chip_pool/addon_pool 下溢会在修改牌组、聚合公钥、座位或事件前
fail-closed，不再用 saturating arithmetic 静默截断坏状态。

proof 在当次原生验证后仍不会被压缩成可转移的 recursive proof；因此这只是
可信宿主进程内的 O(N) 接受产物。

这里的“可信”依赖外部锚：`ExpectedChainAnchor` 校验 table/hand、精确 receipt 数量与
call_seq 范围、链首/链尾 full-width state root/version，以及每个
`dispatch_call_digest`。这些 anchor 字段必须来自已认证 block/receipt；若从同一批
待证 task 反推 anchor，不会增加信任。Orchestrator 能证明“给定 pre-state 上的完整
dispatch replay 与 proof 均被 host 接受”，但不能单靠任务里自带的 `DispatchContext`
证明调用真实被区块收录。

当前 wire metadata 的 `table_id` 是 `ObjectID.creation_nonce`，本身不是跨 creator
全局唯一。action 泛型 verifier 已把它绑定到 canonical pre/post table；可信链还依赖
包含完整 `ObjectID` 的 full-width state roots。后续若升级公开 schema，宜直接锚定完整
`ObjectID`（或其共识 key），而不是只把 nonce 当作全局桌号。

### 现有递归基础设施（公开输入重标记漏洞已修复，完整递归仍不 sound）
`poker_zkvm::stwo_backend::recursive` 的 P05-R public-input binding 已加固：统一的
`RecursivePublicInputs::mix_into` 现在以域分隔、长度前缀、完整 felt252/u64 编码绑定
`l1_commitments`、`fri_first_layer_commitment`、`fri_last_layer_poly`、
`query_positions`、`log_size` 以及其余 OODS/FRI 字段。审计回归验证同一个 L2 proof
在任一字段被替换后均失败。

但完整递归仍有以下缺口：
1. ~~Merkle 组件在 `query_positions` 为空时仍是 no-op(`trace_gen.rs:881-885`)~~
   **已收窄闭合（P05-R gap #1）**：`prove_recursive[_with_fri]` 与
   `verify_recursive[_with_fri]` 入口现新增 `ensure_nonempty_public_inputs` 守卫，
   空的 `l1_commitments` / `query_positions` / `log_size==0` 一律返回
   `L1CommitmentsMissing` / `QueryPositionsMissing` / `InvalidLogSize`；
   `gen_merkle_path_trace` 的空-query 早退分支已删除。审计 e2e 已改为从真实 L1 proof
   提取 `commitments`（`l1_proof.0.commitments`）与 transcript-sampled
   `query_positions`（新增 `extract_query_positions_from_l1`），使 Merkle Path AIR
   不再走 no-op 路径。
   - **gap #3-A（felt252→M31 编码非法/有损，已闭合）**：深入后发现 `field_element_252_to_m31_limbs`
     原把 felt252 大端字节切成 8×32-bit chunk 直接 `from_u32_unchecked` 装入 M31，但 32-bit chunk
     可达 `2^32-1` 远超 M31 的 `2^31-1`，debug profile 下 `partial_reduce` add-with-overflow panic
     （release 下静默产生非法 M31）。上一版改成 8×31-bit 后虽然不 panic，却又截断 felt252 高 4 bit，
     且 radix `2^31` 的 digit `2^31-1` 本身等于 M31 模数、仍不是合法 canonical field element。
     现改为 **9-limb radix-(2^31-1)** 小端分解，每个 limb 严格小于 M31 模数，编码/解码完整可逆；
     新增高于 bit 248 的碰撞回归和 `FieldElement252::MAX` 往返回归。
   - **gap #3-B（旧 Merkle verifier AIR 已确认错误并退役）**：对照 Stwo 2.3 后确认，
     `MerkleDecommitmentLifted.hash_witness` 是跨 query 合并、仅在 sibling 未由其他 query 推导时才消费的
     压缩序列；当前 `query_idx * tree_height + layer_idx` 的 dense-path 索引模型错误，且只触及
     `decommitments[0]`/`l1_commitments[0]`。leaf 构造也没有携带 verifier 侧的 per-tree column log sizes，
     无法复现 Stwo 对列排序和 row hashing。更关键的是 `MerklePathAir` 的所谓 Poseidon 约束仍只是
     `parent_limb = left_limb * right_limb`，并未约束 Starknet Poseidon252。故真实数据上的
     `Constraints not satisfied` 只是偶然失败，不是安全边界；恶意输入仍可能满足这些错误多项式。
     `prove_recursive_with_fri` / `verify_recursive_with_fri` 在 crate 内测试路径显式返回
     `IncompleteMerkleVerifierAir`；回归测试
     `gap3b_incomplete_merkle_air_is_explicitly_disabled` 固化这一 fail-closed 行为。相关成功往返测试继续
     `#[ignore]`，直到新 semantic AIR 完成密码学审计。旧 `MerklePathAir` / `FriVerifierAir` 及对应
     trace/padding 已从完整 scaffold 移除，模块仅作为 crate-private 历史 PoC 保留，外部调用方不能绕过
     高层 gate 直接复用。
   - **gap #3-B replay 子层（2026-07-31 进展）**：新增 `RecursiveTreeMetadata`，把每棵
     commitment tree 的原始 column log sizes 加入递归 statement 并纳入 transcript；同时绑定
     全部 FRI inner-layer commitments。`stwo_replay.rs` 已逐步复现 Stwo 2.3 的列按 log-size
     排序、重复 query 检查、Poseidon leaf hashing、兄弟 query 合并、压缩 `hash_witness` 顺序消费、
     preprocessed query lifting 与全部 PCS tree root 检查。真实 CPU L1 proof 的 tree 0/original/
     composition 三棵树均可重放，篡改 queried value、压缩 sibling 或 column metadata 会失败。
   - **完整 FRI replay 子层（2026-07-31 进展）**：新增 `fri_replay.rs`，复现 first/inner layer
     `fri_witness` 补齐、packed leaf Merkle opening、circle→line/line folding、末层多 query polynomial
     evaluation，并对真实 L1 proof 与篡改 witness/last polynomial 做回归。该模块提供 canonical witness
     生成与主机侧交叉检查；后续 `fri_semantic_air.rs` 已消费这些 witness，但仍需整体组合审计。
   - **新确认的组合 soundness 前置条件**：generic `StarkProof` 本身不携带 verifier components、
     interaction challenge/claimed-sum 的 method-specific transcript schema，也不能仅凭 tree metadata
     重建 `Components::mask_points` 与 composition constraint evaluation。故真实闭合不仅需要
     Poseidon252 non-native AIR，还必须把固定 method verifier（component layout、interaction 消息、
     OODS composition evaluation）作为递归 verifier program 的一部分；不能让 prover 自报 transcript
     schedule。当前 simple transcript replay 仅用于 padding-only 单 CPU proof 回归，禁止泛化到 Texas
     多组件 proof。
   - **fixed `CpuV1` verifier program（2026-07-31 进展）**：递归 statement 新增代码内固定的
     `RecursiveVerifierProgram::CpuV1`，并把 program id、composition random coefficient、FRI quotient
     random coefficient 纳入公开输入 transcript。`build_cpu_recursive_public_inputs` 只从真实
     `prove_cpu_trace` proof 构造 statement；`replay_cpu_verifier` 精确重建 `CpuAir` component、
     `Components::column_log_sizes()` / `mask_points()`、Poseidon252 transcript 派生的 composition/OODS/FRI
     challenges、真实 `CpuAir` composition OODS evaluation、`fri_answers`、全部 PCS Merkle trees 和完整
     FRI replay。`_with_fri` 在 fail-closed gate 前先执行该固定 replay，因此 prover 不能再提供通用的
     component layout 或 transcript schedule。
   - **fixed CPU composition AIR 子层（2026-07-31 进展）**：原 10 列 no-op
     `CompositionEvalAir` 已替换。新 AIR 读取 `CpuV1` original tree 的 185 个 QM31 OODS samples
     （740 个 M31 columns），通过 nested `EvalAtRow` 直接复用 `CpuAir::evaluate`，按 Stwo
     `PointEvaluationAccumulator` 顺序、transcript-derived random coefficient 和 CPU trace-domain
     vanishing denominator 累计全部 constraint quotients，并约束结果等于 claimed composition OODS
     evaluation。真实 proof、篡改 sample、篡改 claim 回归均已添加；`new_bound` 还把 185 个 samples
     固定到 verifier-known claim。后续 PCS quotient AIR 已把同一组 samples 接到 canonical Merkle queried
     values，`CpuTranscriptBindingAir` 也把 composition random coefficient、OODS point 和 FRI quotient
     coefficient 接到 transcript draw result。`OodsCheckAir::new_bound` 现额外绑定公开 composition claim、
     `oods_point.repeated_double(...).x` 与 8 个 composition-tree samples，并强制四行均为 active 重复检查，
     消除 all-padding 绕过。
   - **官方 Poseidon252 AIR 闭包（2026-07-31）**：已接入 `cairo-air = 1.2.2`，并仅 vendor
     `stwo-cairo-common/prover = 1.2.2` 的 witness 侧代码；对当前 nightly 的 patch 仅包含
     `Mask::to_int`、已删除 `array_chunks` feature 与 slice `array_chunks` 三类机械兼容修改。
     `poseidon252_air.rs` 现装配官方 `PoseidonAggregator`、full/partial round、cube、round keys、
     `MemoryIdToBig/Small` 与全部依赖 range-check components。逐组件 `assert_constraints_on_trace`
     回归已通过，caller + 官方闭包的 lookup claimed sums 精确归零；非法 native permutation 在 witness
     生成前拒绝。该结论只覆盖单次 permutation 算术闭包，不代表 transcript/Merkle/FRI 已组合 sound。
   - **Poseidon/transcript canonical witness 子层（2026-07-31 进展）**：新增
     `poseidon252_replay.rs`，逐操作镜像 Stwo 2.3 `Poseidon252Channel`、lifted Merkle leaf finalize 与
     parent hash，把 transcript mix-root/mix-felts/mix-u32s/mix-u64、challenge/query draw、PoW prefix/
     nonce 检查以及全部 Merkle leaf/parent 的每一次三元 Hades permutation 记录为精确
     `(input_state, output_state, call_kind)`。`FriReplayChallenges` 现同时携带 transcript event 边界、
     digest/n_draws 前后状态、精确 sponge absorbed values 和对应 call ranges；PCS 与 FRI Merkle replay
     也携带 leaf 原始 M31 row、leaf call range、parent step 与压缩 witness index。新增
     `CanonicalVerifierWitness` 按 transcript → PCS trees → FRI layer trees 的稳定顺序展平所有调用，
     同时保存每棵 tree/leaf/parent 到全局 Poseidon call index 的稳定映射，以及每层 FRI 的完整 pre-fold
     coset evaluations、domain initial indexes、folded positions 与 folded evaluations。真实 CPU proof
     回归验证上述映射覆盖全部 PCS/FRI trees 和 committed FRI layers。
   - **caller committed binding（2026-07-31）**：canonical caller 为每个 felt252 分配 deterministic
     synthetic Cairo memory ID，并通过六条 `MemoryIdToBig(id, 28×9-bit limbs)` lookup 与官方
     `PoseidonAggregator(input_ids, output_ids)` 连接。此前 168 个 value limbs 错放在 witness 派生的
     preprocessed columns，现已全部移入 committed base trace；caller 同时提交 active/source/index/kind
     selectors，AIR 约束 selector boolean/one-hot、transcript/Merkle source-kind 分离，以及 pair hash 的
     domain separator `2` 和 draw 的 separator `3`。真实 canonical witness 已可直接生成该官方闭包 trace。
     `_with_fri` 的 crate 内 fail-closed 路径现会在关闭 gate 前完成该 canonical closure 的 base/
     interaction witness 装配与 lookup balance 审计，避免后续打开 gate 时才发现真实 proof 布局不兼容。
2. 递归只包裹**单个** L1 proof，**无 N-proof 聚合机制**（未变）。
3. 递归只测试过 trivial padding CPU trace，从未跑过真实 Texas method AIR
   （未变；且 `poker_zkvm` 的 guest crate `guests/texas_poker` 本轮尚未迁入 zchain
   workspace，真实 method proof 端到端路径暂不可用）。

由于整体 relation/multiplicity/transcript 顺序尚未完成独立密码学审计，当前不能排除恶意 prover
针对边界条件构造满足局部 AIR 的错误 L2 proof；因此
`poker_zkvm` 的 OODS-only 实验路径仅在 crate 自身 `cfg(test)` 中执行；含 FRI/Merkle 的
`*_with_fri` 路径在 crate 内也因 `IncompleteMerkleVerifierAir` fail-closed。跨 crate 调用
统一返回 `UnsoundBackendDisabled`。L1 的 `StwoZkVerifier` 即使治理状态为 Production 也
返回 `verified = false`，不再使用 `RecursivePublicInputs::default()` 接受未绑定
`ZkPublicIo` 的 proof。

### 修复路径(均需密码学专家)
- **(a) 让单 proof 递归 sound**：公开输入/transcript binding、官方 Cairo Poseidon252 closure、
  compressed multi-query Merkle semantic/leaf AIR、PCS quotient、完整默认 FRI fold、fixed `CpuV1`
  composition/OODS AIR 及三棵 commitment scaffold 已实现。**仍需**独立密码学审计全部 relation 的符号、
  multiplicity、selector 与 transcript 顺序，打开 gate 后完成真实 L2 prove/verify roundtrip 和 adversarial
  proof-envelope 篡改测试，并把 fixed program 扩展/集成到真实 Texas method AIR；审计前不得打开 gate。
- **(b) 构建 N-proof 聚合**:在 sound 的单 proof 递归之上,设计二叉树折叠或专用多验证器 AIR。(~1-2 周 + 设计决策)
- **(c) host-side 逐子验证**(已实现的过渡路径):host 对每个子 proof 跑
  `stwo::verify()`，只允许 verifier-issued receipt 进入 `VerifiedChain`。该路径失去
  succinctness，验证方仍需 O(N) 全验证；仅作过渡姿态。

### 结论
**真正的 recursive/succinct 聚合仍不可机械修复。** 需完成单 proof 的密码学审计与 gate 后 E2E，
再用约 ~(1)周集成到真实 method AIR +
~(1-2)周设计 N-proof 聚合 + 密码学 sign-off。

**当前状态**：
- descriptor-only prove/verify 生产入口继续 fail-closed；
- `poker_zkvm` recursive PoC 与 L1 `StwoZkVerifier` 生产路径均 fail-closed；
- `poker_zkvm` 主 crate 已迁入 zchain workspace（`members` 含 `poker_zkvm`）；其
  guest 子 crate（`guest_sdk` / `guests/texas_poker`）暂未迁入，依赖它们的 E2E
  测试与 bench 暂留外部目录；
- `test-helpers` 已从 root / `poker_l1` 普通依赖移除，仅保留在 `poker_l1` dev-dependency；
  release 依赖图不再暴露测试 ELF/证明构造器；
- **P05-R gap #1**（空-input Merkle no-op）已收窄闭合 + 回归（守卫拒绝空 commitments/query/log_size）；
  **gap #3-A**（felt252→M31 非法/有损编码）已修复为 9-limb radix-(2^31-1) 无损编码；
  **gap #3-B** 中 host canonical replay 部分（压缩 multi-query witness、全 tree commitment、column
  metadata、完整 FRI layer folding/decommitment）已实现并有真实 proof/篡改回归；transcript、PCS
  Merkle 与 FRI Merkle 的每次 Poseidon252 permutation 现也已按 canonical 执行顺序记录；transcript
  event 状态、Merkle leaf row/call range/parent 全局索引和 FRI 每层 pre-fold coset witness 已固定展平。
  官方 Cairo Poseidon252 non-native 算术闭包与 committed canonical caller AIR 已落地；caller 现通过
  22 元组（global/source/kind metadata + 6 synthetic memory IDs）负向导出 canonical call，独立
  semantic mirror 正向消费，并再次用 6 条 `MemoryIdToBig` lookup 绑定相同 committed 28×9-bit
  limbs，官方 closure + caller + semantic 的全局 claimed sum 已审计为零。canonical witness 还显式
  展开 transcript event→call 键、Merkle leaf/witness/parent/child/root node 多重集，以及 FRI Merkle
  leaf→opened coset、folded layer→next layer/last layer 的稳定连接；对应 host tamper 回归已加入。
  L2 scaffold 已能按固定 preprocessed / heterogeneous base / interaction 三棵 tree 的顺序装配全部
  Cairo Poseidon closure、caller、semantic mirror 与现有 OODS/FRI/Merkle/composition components；
  closure claims/claimed sums 会进入 proof envelope 和 Fiat–Shamir channel，verifier 重算并强制固定
  preprocessed commitment root，而不是接受 prover 任意 root。

  **transcript semantic AIR（2026-07-31 下一阶段）** 已新增：generic semantic mirror 现在对 transcript
  source 额外负向导出 `TranscriptPoseidonCall` 18 元组（global/source index、10 个 kind selector、6 个
  synthetic memory ID），逐调用 transcript table 正向消费；六条额外 `MemoryIdToBig` lookup 把 table
  中的 28×9-bit limbs 重新绑定到同一官方 Cairo memory。AIR 按 Stwo circle-domain coset 顺序约束
  call/event index、first/last/call-count、event 间 digest 与 draw-counter 链、mix 后 counter reset、draw
  counter `+1` 及其三 limb 精确编码、single-call kind、首 digest 为零、mix/draw/pow 的 digest
  before/after/result 与 Poseidon input/output limb 等值，以及多调用 sponge 的 state[2] 连续性。Poseidon
  caller active 与 transcript active/first/last 都改为 verifier 由 `(log_size, n_calls)` 重建的固定
  preprocessed columns；对应 commitment root、claim/channel、base/interaction tree 列数和第 17 个
  transcript component 已同时装配到 `_with_fri` prover/verifier scaffold。篡改 active/event chain 回归和
  caller+semantic+transcript+官方 closure 全局 LogUp 归零回归已加入。

  **felt252 transcript addition closure（2026-07-31 后续阶段）** 已继续闭合：每个非-draw absorbed felt
  现在拥有 synthetic Cairo memory ID，并通过新增 `MemoryIdToBig` lookup 绑定精确 28×9-bit limbs；pair
  hash 的两个 payload 直接等于 permutation input，`hash_many` 则逐调用约束前一 state、两个 payload、
  odd/even 末块 `+1` padding 与当前 permutation input。模加使用 `P_FELTS`、单个 subtract-prime bit 和
  每 limb 互斥正/负 carry bit，证明
  `state + payload + padding = input + q·p`，且 AIR degree 仍为 2。payload lookup 增加后，transcript 共导出
  12 条 semantic relation；官方 memory multiplicity、caller/semantic/transcript 全局 LogUp 再次归零。新增
  回归覆盖 payload limb 篡改、carry 篡改与 `p-1+1=0 mod p`，真实 CpuV1 canonical replay audit 也通过。

  **Merkle semantic / leaf AIR（2026-07-31 后续阶段）** 已新增：public binding table 固定全部 PCS/FRI
  roots、tree/layer/source metadata 与 query schedule；semantic table 用 child/parent/root node multiset
  重放 compressed multi-query，并通过 caller relation 消费每次 canonical Poseidon252 leaf/parent call。
  leaf packing AIR 约束 Stwo lifted leaf 的 M31→felt252 packing、模加 carry/padding 和 memory lookup；每个
  active leaf value 还正向导出 keyed `MerkleQueriedValue(relation_id, pcs_source, fri_source, source_arg,
  node_index, leaf_value_index, value)`。leaf interaction columns 因 23 条 relation 增至 **48**。

  **PCS quotient / complete default FRI fold AIR（2026-07-31 后续阶段）** 已新增：PCS quotient table 按
  Stwo 官方 `ColumnSampleBatch` / `quotient_constants` / `accumulate_row_quotients` 的 column order，把每个
  `fri_answer` 表示为 `baseline + Σ queried_value_i * coefficient_i`，逐项消费上述 Merkle queried-value
  relation，并导出 keyed QM31 query value；其 base/interaction columns 为 **9 / 4**。FRI fold table 每行
  消费 committed FRI leaf 的左右 QM31（8 个 M31 lookup），约束 circle→line/line fold
  `f0=left+right`、`f1=(left-right)*inverse_twiddle`、`output=f0+alpha*f1`，逐层 keyed 传递并在末层绑定
  degree-zero last-layer coefficient；其 base/interaction columns 为 **12 / 24**。当前实现明确只接受
  `CpuV1 + PcsConfig::default()`、`fold_step=1`、`log_last_layer_degree_bound=0`。

  **完整 L2 三树装配与旧占位清理（2026-07-31）**：上述 transcript/Merkle/leaf/quotient/fold tables
  已按完全相同顺序装入 prover/verifier 的 fixed preprocessed tree、heterogeneous committed base tree 与
  interaction tree；全部 claimed sums 进入 Fiat–Shamir channel，canonical 全局 lookup sum 必须精确归零。
  旧 `FriVerifierAir` / `MerklePathAir`、对应 trace/padding 与 log-size entries 已从完整 `_with_fri`
  scaffold 移除，避免未来打开 gate 时被错误占位多项式拒绝真实 proof。`OodsCheckAir` 同时补上公开 claim、
  doubling factor、sample exact binding 与 all-padding 回归。

  **LogUp 与 tree metadata soundness 修复（2026-07-31）**：transcript 的 12 条 relation 已从
  `finalize_logup_in_pairs` 拆为 12 个独立 QM31 interaction 列（即 **48 个 M31 物理列**），避免不同 relation
  的分子/分母在同一 LogUp 列内相互抵消。拆分后暴露出 witness writer 与 AIR 的 payload relation 顺序错位：
  writer 原先先写两个 memory relation、再写两个 semantic relation，而 AIR 按 slot 交错消费；现已统一为
  `poseidon -> 6×call-memory -> slot0 memory/semantic -> slot1 memory/semantic -> result`。Merkle interaction
  metadata 也已改为实际提交的 M31 物理列数：semantic **28** 列、public binding **4** 列；此前把逻辑
  relation/半列数误当物理列数，导致 verifier 期望 624 列而 proof 提交 640 列。

  **完整 scaffold gate 后回归（2026-07-31）**：test-only gate bypass 已完成全部 9 个 verifier 组件与
  Cairo Poseidon closure 的真实 L2 prove/verify roundtrip。回归复用同一 proof 验证了篡改
  `RecursivePublicInputs`、篡改 proof envelope 中 `RecursivePoseidonClaim` 的 transcript call-count metadata
  均被拒绝，同时未 bypass 的 verifier 仍返回 `IncompleteMerkleVerifierAir`。进一步审计发现全局 lookup
  归零原先只由诚实 prover 调用 `ensure_lookup_balanced`，verifier 会分别接受 envelope 自报的 claimed sums；
  现 verifier 按 Cairo interaction claim 的固定 flatten 顺序，加上 caller/transcript/Merkle/PCS/FRI 全部
  claimed sums，强制总和严格为零，并有 claimed-sum 篡改回归。定位问题时使用的组件限流、trace clone 与
  逐组件 degree audit 代码已删除，prover 恢复固定、无条件装配完整 base/interaction traces。

  完整三-tree L2 装配代码继续位于 `MERKLE_VERIFIER_AIR_COMPLETE=false` gate 之后，不可达且不能视为
  已完成 sound recursion。剩余工作是独立审计全部 relation/multiplicity/selector/transcript 顺序，并集成
  真实 Texas method program；在此之前生产 gate 必须保持 `false`，test-only bypass 的成功不能作为启用依据。
  `_with_fri` 继续显式 `IncompleteMerkleVerifierAir` fail-closed，不再依赖偶然的
  `Constraints not satisfied`（回归测试 `gap3b_incomplete_merkle_air_is_explicitly_disabled`）；
  gap #2（N-proof 聚合）、gap #3 的组合审计/真实 method proof 端到端仍未闭合；
  `poker_zkvm` 当前定向回归覆盖 OODS/public binding、composition bound、transcript/Poseidon、Merkle
  semantic/leaf、PCS quotient、FRI fold、全局 lookup 归零、空输入守卫、9-limb 无损往返、完整 scaffold
  往返、statement/envelope tamper 与显式关闭；
- **P05-H-core** O(N) 宿主验证与完整范围 anchor 校验已闭合；
- **P05-H-source** 已闭合：`build_anchor_from_consensus` 从已认证 block/cert + SMT 包含证明
  构造 `ExpectedChainAnchor`，`verify_chain_against_consensus` 走锚定路径；剩余边界是
  调用顺序依赖 Bullshark projection（共识层不签名有序序列）；
- **P05-R** 单个可转移的 recursive aggregate proof 仍是已知未完成特性。

---

## P0-6:下注语义的 mid-round 收窄与完整 VM transition 缺口

### 根因
VM 的 `apply_call`/`apply_raise`/`apply_bet` **不是单步 seat 更新**——它们在更新 seat 字段后**无条件调用 `advance_turn`**(`state_machine.rs:2110`/`2185`,bet 经 `3367` 委托 raise)。

`advance_turn`(`state_machine.rs:557-570`)分支:
- **mid-round**(`is_betting_complete==false`):仅推进 `current_turn`。pot/round_state 不变。
- **end-of-round**(`is_betting_complete==true`):`collect_bets_to_pot`(`573-599`)扫所有 seat 的 bet→pot 并清零;`advance_round`(`604-659`)改变 round_state(PREFLOP→FLOP→...→SHOWDOWN),可能触发结算(`end_without_showdown`/`settle_hand`)。

当前 Rust P06 改动选择了诚实的收窄边界：生产任务只在 post-state 仍是
same round、pot 不变、`betting_round/current_turn = Some(next)` 时构造动作 AIR；
收池、推进和结算分支返回 `UnsupportedBettingTransition`，不伪装成已证明。
该守卫覆盖 fold/check/call/raise/bet/auto_fold/force_fold 七个会推进 turn 的动作。

`kick_player` 还有一条独立的复合转移边界：在 `WAITING` 状态踢掉最后一个活跃玩家时，
VM 可能在 `kick_player_internal` 内触发 `reset_for_next_hand`，随后 dispatch 再次
`bump_version`，因此一个 selector 会产生 reset/清理和多次 version bump。生产
Orchestrator 只接受 round 不变、`post_pot = pre_pot + kicked_bet` 且恰好单次 version
推进的 kick；触发嵌套 reset、settlement 或其他多步变化时同样返回
`UnsupportedBettingTransition`，不签发 proof/receipt。

VM 新注册的 `request_leave_after_hand` 与 `fold_with_proof` 仍可进入统一
ProveTask wire format，但生产 Orchestrator 在 dispatch replay/prove 之前显式
`NotImplemented` fail-closed，不生成 proof/receipt；泛型 `prove_method` /
`verify_method_against` 也通过 production AIR allowlist 拒绝二者。尤其 `fold_with_proof` 的
DLEq layer removal 及其可能触发的 advance/settlement 尚未进入可信 AIR。

### 具体反例(heads-up preflop)
SB=BB=10。SB call(amt=0)→ mid-round。BB check 使 `is_betting_complete==true`，则
**单个 apply_check 产生**:
- round_state: PREFLOP→FLOP
- pot: += 20(SB.bet+BB.bet，不是当前动作 amount)
- 两 seat 的 bet 清零
- current_turn: Some→None

**该合法 post-state 不满足 mid-round 谓词。** 当前生产路径对其 fail-closed；
这避免了错证，但也意味着此类常规收尾动作尚无 AIR 覆盖。

### 当前是 mid-round 局部模型
Rust AIR 现约束 actor 的 stack/bet/total_bet 更新、pot/round 不变，并绑定
verifier-trusted pre 金额与 `post_current_turn`。Lean Contract/AIR 的手写逻辑模型也已
同步为 mid-round pot/round 不变，加入 trusted pre-amount、Nat 级 checked-u64
算术、short all-in/conditional min-raise 和下一行动座位绑定；bet 只接受
FLOP/TURN/RIVER。

但尚未证明 Rust physical row layout 与这些 Lean logical records 的逐列/逐约束
refinement，也未建立 `expected_trace_row → BoundAir → transcript → Lean` 桥。
特别地，Lean bet 的 post `current_bet`/`min_raise` 是从 canonical post table 重建的
逻辑字段，当前 Rust `BetRow` 没有对应独立 physical columns。raise/bet 仍未建模
对其他玩家 `acted_this_round` 的重置，也无模型承载多 seat bet sweep、
`current_turn→None`、round 推进和 settlement。
因此只能声称“mid-round 局部路径 fail-closed”，不能声称完整 VM transition
或 Rust↔Lean 精化已证明。

### 修复路径
- **(a) 单 AIR 建模完整 transition**:需多 seat bet-sweep、is_betting_complete 谓词、4 态 round 状态机、side-pot、手牌评估、rake。**极复杂,拒绝。**
- **(b) 多 AIR 分解**(正确的 sound 修复,大重设计):
  1. seat-update AIR(≈现有,但 post-state 弱化为 advance_turn 前的中间快照)
  2. bet-collection AIR(`collect_bets_to_pot` 多 seat 扫)
  3. round-advance AIR(`advance_round` + reveal-phase 触发)
  4. settlement AIR(`end_without_showdown`/`settle_hand`,含手牌评估+side-pot)
  经中间 state root 组合。**可行但量大**:3-4 个新 AIR + 组合层;settlement AIR 继承手牌评估+side-pot 复杂度。
- **(c) 收窄 AIR 声明范围 + mid-round 守卫**(当前过渡路径):
  - 生产任务从真实 pre/post table 提取 trusted 金额和 `post_current_turn`；
  - 仅 same-round、pot unchanged、`current_turn = Some(next)` 时证明；
  - 收池/推进/结算返回不支持，不产生证明；
  - 这是诚实的覆盖收窄，不是完整 P0-6 修复。
- **(d) 纯文档记录为已知限制**:必须伴随 (b) 或 (c)。

### 结论
**完整 P0-6 仍不可靠小补丁闭合。** 根因是 VM 将 seat 更新和
`advance_turn`（可能收注/推进/结算）捆绑在同一个方法中。

- 正确修复 = **(b) 多 AIR 分解**(大重设计,非补丁)
- 务实过渡 = **(c)** 生产 fail-closed 到 mid-round（已实现的收窄方向）
- Lean logical spec 已同步 trusted amounts/next-turn；仍需证明 Rust physical
  row/约束到 Lean 的实现级 refinement
- (a) 不现实；(d) 只能作为边界记录

---

## 总结对照

| P0 | 状态 | 处理建议 |
|---|---|---|
| P0-4 | ✅ **已修复**(`f38bc51` canonical Borsh 全字段) | 可选清理死代码 |
| P0-5 | H-core ✅；H-source ✅；R ❌ | 生产使用 `build_anchor_from_consensus` 构造 consensus-derived `ExpectedChainAnchor` + `verify_chain_against_consensus`；succinct 聚合仍需密码学专家 |
| P0-6 | mid-round 生产路径已收窄；full transition ❌ | 继续 fail-closed；收池/推进/结算需多 AIR 重设计 |
