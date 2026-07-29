import PokerLean.Audit.TrustBoundary

/-!
# AIR Soundness 审计结论

当前 21 个 `*_air_sound` 定理都是有效的 Lean 定理，但结论必须限定为：

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

## Rust AIR 结构缺陷修复进展（不影响上述 Lean 结论，但记录 AIR 侧改进）

经端到端复审发现的若干 P0 级 Rust AIR 结构缺陷已修复（全量 `cargo test` 140/140 通过）：

- **P0-1（全 padding trace 绕过）已修复**：`common.rs` 增加无条件约束 `is_active = 1`，
  彻底关闭 all-padding trace 绕过所有 `is_active`-门控业务约束的攻击。
- **P0-2（多 limb 等式相加可抵消）已修复**：`pot_unchanged_4limb`、`pot_delta_4limb`、
  `limb4_delta`、`limb4_delta_rev`、`limb4_eq`、`ge_4limb`、`bound_check_4limb`、`range16`
  全部改为**逐 limb 独立 `add_constraint`**（返回 `Vec`，调用点循环），不再求和成单约束。
  消除了 limb 间互相抵消（如残差 (+1, -1) 求和为 0 仍通过）的攻击。
- **P0-3（state_root 与 trace 无连接）已修复**：`state_root_to_air_limbs` 做真实
  Blake2b→4×M31 转换（不再是全零占位）；`CommonConstraints::write` 强制 trace 的
  state_root/table_id/hand_id/call_seq/version 列 == AIR statement 的对应值。
- **e2e 测试债修复**：合成机制测试改用与 AIR statement 自洽的 PI/roots
  （`synthetic_for_test` + `synthetic_air_roots`），通过加强后的 `verify_air_statement`。

**仍未建立（端到端闭环的剩余阻断项，按优先级）**：
- ✅ **P0-4：已修复**。`table_state_preimage` 与 `SeatLeaf::from_seat` 现用 canonical Borsh
  序列化整个 `TexasPokerTable`/`Seat`（域分隔 tag `*.v2`），全字段自动覆盖，手工字段列表
  已移除。addon_pool/ante/rake/RIT/bet/total_bet/folded/all_in 等均包含。仅余死代码清理（cosmetic）。
- ❌ **P0-5：不可机械修复（需密码学专家）**。Aggregator 仍 descriptor-only，不验证子 proof。
  现有 `poker_zkvm` 递归层被项目自身审计测试标记为 unsound（L1 commitment 未 mix 进 channel、
  Merkle 组件 no-op、无 N-proof 聚合）。修复需 ~(1)月专家工作。详见
  `poker_texas_air/docs/PO5_PO6_DESIGN_NOTES.md`。生产入口已 fail-closed。
- ❌ **P0-6：不可机械修复（最难，根本性建模缺口）**。VM 的 call/raise/bet 在 seat 更新后
  无条件调用 `advance_turn`，可能收注（pot 跳变、清零所有 seat bet）、推进 round、结算；
  而 AIR/Lean 固定要求 round 不变、pot 只增本次金额。单个 VM-legal 收尾动作常规性违反 AIR。
  正确修复 = 多 AIR 分解（seat-update + bet-collection + round-advance + settlement）；务实过渡
  = 收窄 AIR 范围 + `current_turn ≠ None` 守卫（覆盖部分）。详见同上文档。
- Lean 侧桥接：Rust `evaluate` ↔ Lean AIR 谓词的逐约束等价、VM 完整精化、密码学子证明验证均未建立。
- 生产接线：tick + 4 crypto 方法未接线；2 个 VM 入口无 MethodKind；4 crypto 入口 Borsh 解码 bug。
-/

namespace PokerLean.Audit

#check currentClaimScope
#check lean_model_implications_are_in_scope
#check end_to_end_claim_is_out_of_scope
#check remainingCustomTrustRoots

end PokerLean.Audit
