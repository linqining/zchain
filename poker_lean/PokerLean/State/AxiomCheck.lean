import PokerLean.State.Theorems
import PokerLean.State.Refinement
import PokerLean.State.HandEvaluator

open TexasPoker

-- 抽查顶层定理依赖的 axiom（应仅 propext / Classical.choice / Quot.sound）

#print axioms state_transition_preserves_invariants
#print axioms apply_raise_preserves_core_invariants
#print axioms apply_call_preserves_all_invariants
#print axioms reset_for_next_hand_preserves_all_invariants
#print axioms end_without_showdown_chip_conservation
#print axioms reset_for_next_hand_chip_conservation
#print axioms rust_apply_call_refines
#print axioms rust_apply_raise_refines
#print axioms process_call_panic_free
#print axioms process_raise_panic_free
#print axioms side_pot_conservation
#print axioms TexasPoker.HandRank.hand_rank_total_order
#print axioms TexasPoker.HandRank.evaluate_best_is_maximum
#print axioms subphase_chip_neutral
#print axioms round_monotonic
#print axioms round_no_skip_preflop_to_river
#print axioms round_reset_only_to_waiting
#print axioms shuffle_monotonic
#print axioms reveal_monotonic
#print axioms reconstruct_monotonic
#print axioms BettingRound.process_raise_strictly_increases_current_bet
#print axioms BettingRound.process_raise_min_raise_nondecreasing
#print axioms BettingRound.chips_to_call_correct
#print axioms apply_fold_chip_conservation
#print axioms apply_check_chip_conservation
#print axioms apply_call_chip_conservation
#print axioms apply_raise_chip_conservation
#print axioms apply_addon_chip_conservation
#print axioms apply_rebuy_chip_conservation
#print axioms collect_rake_chip_conservation
#print axioms side_pot_eligibility_nested
#print axioms folded_not_eligible
#print axioms TexasPoker.HandRank.lexLt_is_strict_total_order
#print axioms TexasPoker.HandRank.select_best_maximum
