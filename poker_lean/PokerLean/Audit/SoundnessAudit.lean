import PokerLean.Audit.TrustBoundary

/-!
# AIR Soundness 审计结论

当前 selector 0--20 的 21 个 `*_air_sound` 定理都是有效的 Lean 定理，但结论必须限定为：

> 手写 Lean `*AirAcceptable` 谓词蕴含手写 Lean `Contract*` 谓词。

它们不是当前 `poker_texas_air` 与 `poker_l1` 的端到端实现证明。尚未建立的桥包括：

1. Rust `FrameworkEval::evaluate` 与 Lean AIR 谓词的逐约束等价；
2. Rust trace/public-input/state-root 列与 Lean 状态提取函数的等价；
3. VM dispatch、caller/creator 授权、`advance_turn`、结算与 Lean Contract 的完整精化；
4. Aggregator 对子 proof 的递归验证；
5. DLEq、shuffle、reveal、reconstruct 等密码学子证明验证。

因此，不应再使用“21/21 已完整 sound”“已验证真实 Rust AIR”或“已闭合所有
soundness gap”等表述。机器可检查的范围声明和公理输出见
`PokerLean.Audit.TrustBoundary`。

Rust/VM 当前已有 23 个 selector；21 `request_leave_after_hand` 与 22
`fold_with_proof` 不在 Lean `MethodKind` 中，也没有对应模型内定理。

## Rust AIR 结构缺陷修复进展（不影响上述 Lean 结论，但记录 AIR 侧改进）

经端到端复审发现的若干 P0 级 Rust AIR 结构缺陷已修复；Rust 测试结果应以当前
工作树重新执行的输出为准：

- **P0-1（全 padding trace 绕过）已修复**：`common.rs` 增加无条件约束 `is_active = 1`，
  彻底关闭 all-padding trace 绕过所有 `is_active`-门控业务约束的攻击。
- **P0-2（多 limb 等式相加可抵消）已修复**：`pot_unchanged_4limb`、`pot_delta_4limb`、
  `limb4_delta`、`limb4_delta_rev`、`limb4_eq`、`ge_4limb`、`bound_check_4limb`、`range16`
  全部改为**逐 limb 独立 `add_constraint`**（返回 `Vec`，调用点循环），不再求和成单约束。
  消除了 limb 间互相抵消（如残差 (+1, -1) 求和为 0 仍通过）的攻击。
- **资金加法 carry-chain 已修复**：addon 的 pending/addon_pool、rebuy 的 stack/addon_pool、
  kick_player 的 pot 均加入 3 个 boolean ripple-carry witness；Rust AIR、真实 VM replay 回归
  与 Lean `Limb4Delta`/`PotDelta` 现一致覆盖跨 16-bit limb 的合法 `checked_add` 转移。
- **leave_table 资金 carry-chain 已修复**：refund 使用规范 `Limb4Delta`；chip_pool/addon_pool
  减法使用 `Limb4DeltaRev`（即 `pre = post + amount`）表达跨 limb 借位并禁止下溢；Rust
  trace、宿主 fail-closed 校验、真实 VM replay 回归与 Lean refinement 已同步。
- **离座退款的 VM checked arithmetic 已补齐**：`leave_table` 与
  `leave_with_proof` 均不再使用 `saturating_add/sub`。refund 溢出、chip_pool/addon_pool
  下溢会在任何座位/牌组/公钥变更前拒绝，失败路径保持原子性。
  `leave_with_proof` AIR 本身仍未内建退款列约束，当前由严格 VM replay 绑定。
- **生产 Mental Poker 密码学 skip 已关闭**：`TableConfig` 保留旧 `zk_skip_*`
  字段以兼容序列化状态，但它们只在 `poker_l1` crate 自身 `cfg(test)`
  单元测试中生效。普通库、集成测试和生产构建的 VM replay 对
  shuffle/reveal/reconstruct/remask 始终执行真实 verifier，不再依赖
  尚未实现的 governance 强制。
- **P0-3（state_root 与 trace 无连接）已修复**：`state_root_to_air_limbs` 做真实
  Blake2b→4×M31 转换（不再是全零占位）；`CommonConstraints::write` 强制 trace 的
  state_root/table_id/hand_id/call_seq/version 列 == AIR statement 的对应值。
- **e2e 测试债修复**：合成机制测试改用与 AIR statement 自洽的 PI/roots
  （`synthetic_for_test` + `synthetic_air_roots`），通过加强后的 `verify_air_statement`。

**仍未建立（端到端闭环的剩余阻断项，按优先级）**：
- ✅ **P0-4：已修复**。`table_state_preimage` 与 `SeatLeaf::from_seat` 现用 canonical Borsh
  序列化整个 `TexasPokerTable`/`Seat`（域分隔 tag `*.v2`），全字段自动覆盖，手工字段列表
  已移除。addon_pool/ante/rake/RIT/bet/total_bet/folded/all_in 等均包含。仅余死代码清理（cosmetic）。
- ⚠️ **P0-5 已拆分可信边界**。P05-H-core 的 Rust host O(N) 路径已实现：公开 VM
  dispatch 重放成功后逐个调用原生 verifier，只由 verifier-issued receipt 构造
  `VerifiedChain`，并可对精确范围执行 `ExpectedChainAnchor` 校验。P05-H-source 仍需
  上层从已认证 block/receipt 提供 anchor；当前本地 proving service 未接入共识来源。
  P05-R 的 public-input transcript 重标记漏洞已修复：commitments、FRI root/poly、queries、
  log_size 与 OODS/FRI 字段现统一绑定，篡改单字段会使 L2 verify 失败。但 recursive/succinct
  aggregator 仍 descriptor-only，Merkle/query 完整验证、`ZkPublicIo` refinement 及
  N-proof aggregation 尚未闭合。因此 `poker_zkvm` recursive API、L1 `StwoZkVerifier`
  与 aggregator 生产入口均继续 fail-closed。两条 Rust 路径均尚无对应 Lean 实现级模型/定理。详见
  `poker_texas_air/docs/PO5_PO6_DESIGN_NOTES.md`。
- ⚠️ **P0-6：mid-round 生产路径已收窄，完整 transition 仍未完成**。VM 的
  call/raise/bet 在 seat 更新后无条件调用 `advance_turn`，收尾分支会收注
  （pot 跳变、清零多个 seat bet）、推进 round 或结算。Rust P06 改动现将
  生产证明限定为 same-round + pot unchanged + `current_turn = Some(next)` 的
  mid-round 分支，对 end-of-round/settlement fail-closed。Lean call/raise/bet 已同步为
  pot/round 不变的 mid-round 局部谓词，并在手写逻辑 AIR 中加入 verifier-trusted
  pre-amount、checked-u64 的 Nat 级规则、actor `all_in`、short all-in/conditional
  min-raise 与 `post_current_turn`；bet 只允许 FLOP/TURN/RIVER。

  这仍不是 P0-6 完整修复：尚未建立 Rust physical row、
  `expected_trace_row → BoundAir → transcript` 与这些 Lean logical records 的逐列/逐约束
  refinement。特别地，Lean bet 的 post `current_bet`/`min_raise` 是从 canonical post table
  重建的逻辑字段，并非当前 Rust `BetRow` 的独立 physical columns。Lean raise/bet 仍未
  建模重置其他玩家 `acted_this_round`；bet-collection、round-advance 与 settlement
  AIR/精化也仍缺失。详见同上文档。
- Lean 侧桥接：Rust `evaluate` ↔ Lean AIR 谓词的逐约束等价、VM 完整精化、密码学子证明验证均未建立。
  Crypto method AIR 本身仍只描述协议状态变更；当前安全性来自生产
  Orchestrator 的严格原生 VM replay，不是可转移的 recursive crypto proof。
- selector 21/22：Rust 统一 wire format 已登记，但生产 proof/receipt 路径显式
  fail-closed；Lean 侧也尚无 MethodKind、AIR/Contract 或 soundness theorem。
-/

namespace PokerLean.Audit

#check currentClaimScope
#check lean_model_implications_are_in_scope
#check end_to_end_claim_is_out_of_scope
#check remainingCustomTrustRoots

end PokerLean.Audit
