import PokerLean.Proofs.CreateTableSoundness
import PokerLean.Proofs.FoldSoundness
import PokerLean.Proofs.CheckSoundness
import PokerLean.Proofs.CallSoundness
import PokerLean.Proofs.RaiseSoundness
import PokerLean.Proofs.BetSoundness
import PokerLean.Proofs.MoreActionsSoundness
import PokerLean.Proofs.JoinTableSoundness
import PokerLean.Proofs.LeaveTableSoundness
import PokerLean.Proofs.LifecycleSoundness
import PokerLean.Proofs.FundsSoundness
import PokerLean.Proofs.CryptoSoundness

/-!
# 当前形式化的信任边界

本模块是默认构建的一部分，用机器可检查的声明区分：

* 已建立：手写 Lean `*AirAcceptable` 谓词蕴含手写 Lean `Contract*` 谓词；
* 未建立：真实 Rust AIR 与 Lean AIR 谓词等价；
* 未建立：真实 VM 完整状态转移精化到 Lean Contract/State 模型；
* 未建立：公开输入、state-root、聚合器和密码学子证明的端到端验证。

Lean `MethodKind` 当前只登记 selector 0--20 的 21 个手写模型。Rust/VM 已扩展到
23 个 selector；21 `request_leave_after_hand` 与 22 `fold_with_proof` 没有 Lean
`AirAcceptable → Contract` 定理，且 Rust 生产证明路径目前对二者 fail-closed。

其中 call/raise/bet 的 `Contract*` 与 `*AirAcceptable` 现只表达
mid-round 局部片段（pot/round 不变）。end-of-round 收池、round 推进与
settlement 不在这些定理的结论中。

这三个手写逻辑 AIR 已包含 verifier-trusted pre-state 金额、Nat 级 checked-u64
算术事实、actor `all_in` 更新和 `post_current_turn` 绑定；bet 只允许
FLOP/TURN/RIVER。它们仍不是 Rust
physical row layout 的形式化镜像。尤其 bet 的 post `current_bet`/`min_raise` 是
canonical post table 的逻辑重建字段，不是当前 Rust `BetRow` 的独立物理列。

Rust 生产路径的 `expected_trace_row → BoundAir → transcript`
绑定，以及已实现的“原生验证后签发 `VerificationReceipt` 并构造
`VerifiedChain`”host-side 流程，尚无对应 Lean 模型/定理。

文件末尾的 `#print axioms` 会在 Lean 编译本模块时检查并打印上述 21 个模型内
soundness 定理的实际公理依赖。当前预期的自定义信任根只有：
`PokerLean.poseidon_hash` 与 `PokerLean.texasPokerTableToPreimage`。
-/

namespace PokerLean.Audit

/-- 对当前证明覆盖范围的可执行声明。 -/
structure ClaimScope where
  leanModelImplications : Bool
  allVmSelectorsCovered : Bool
  rustAirEquivalence : Bool
  vmEndToEndRefinement : Bool
  publicInputAndRootBinding : Bool
  aggregatorVerification : Bool
  cryptographicSubproofVerification : Bool
deriving Repr, DecidableEq

/-- 当前仓库能够诚实声称的覆盖范围。 -/
def currentClaimScope : ClaimScope where
  leanModelImplications := true
  allVmSelectorsCovered := false
  rustAirEquivalence := false
  vmEndToEndRefinement := false
  publicInputAndRootBinding := false
  aggregatorVerification := false
  cryptographicSubproofVerification := false

/-- 当前证明确实包含模型内蕴含关系。 -/
theorem lean_model_implications_are_in_scope :
    currentClaimScope.leanModelImplications = true := rfl

/-- 当前结果不能被解释为 Rust AIR 到 VM 的端到端形式化验证。 -/
theorem end_to_end_claim_is_out_of_scope :
    currentClaimScope.allVmSelectorsCovered = false ∧
    currentClaimScope.rustAirEquivalence = false ∧
    currentClaimScope.vmEndToEndRefinement = false ∧
    currentClaimScope.publicInputAndRootBinding = false ∧
    currentClaimScope.aggregatorVerification = false ∧
    currentClaimScope.cryptographicSubproofVerification = false := by
  decide

/-- 审计中允许出现的自定义信任根名称；权威依赖仍以 `#print axioms` 输出为准。 -/
def remainingCustomTrustRoots : List String :=
  ["PokerLean.poseidon_hash", "PokerLean.texasPokerTableToPreimage"]

end PokerLean.Audit

/-! ## selector 0--20 的 21 个模型内 soundness 定理机器审计 -/

#print axioms PokerLean.create_table_soundness
#print axioms PokerLean.fold_air_sound
#print axioms PokerLean.check_air_sound
#print axioms PokerLean.call_air_sound
#print axioms PokerLean.raise_air_sound
#print axioms PokerLean.bet_air_sound
#print axioms PokerLean.auto_fold_air_sound
#print axioms PokerLean.force_fold_air_sound
#print axioms PokerLean.kick_player_air_sound
#print axioms PokerLean.join_table_air_sound
#print axioms PokerLean.leave_table_air_sound
#print axioms PokerLean.start_hand_air_sound
#print axioms PokerLean.tick_air_sound
#print axioms PokerLean.reset_for_next_hand_air_sound
#print axioms PokerLean.addon_air_sound
#print axioms PokerLean.rebuy_air_sound
#print axioms PokerLean.join_and_shuffle_air_sound
#print axioms PokerLean.leave_with_proof_air_sound
#print axioms PokerLean.submit_shuffle_v2_air_sound
#print axioms PokerLean.submit_player_reveal_tokens_air_sound
#print axioms PokerLean.submit_reconstruct_deck_air_sound
