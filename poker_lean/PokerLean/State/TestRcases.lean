import Mathlib

-- Test 1: rcases with rfl pattern on explicit Or (3 disjuncts)
example (s s' : Nat)
    (h : (s = 0 ∧ s' = 1) ∨ (s = 1 ∧ s' = 2) ∨ (s' = 0)) :
    s ≤ s' ∨ s' = 0 := by
  rcases h with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | rfl
  · left; omega
  · left; omega
  · right; rfl

-- Test 2: abbrev + change at h + rcases (3 disjuncts)
abbrev MyRel (s s' : Nat) : Prop :=
  (s = 0 ∧ s' = 1) ∨ (s = 1 ∧ s' = 2) ∨ (s' = 0)

example (s s' : Nat) (h : MyRel s s') :
    s ≤ s' ∨ s' = 0 := by
  change (s = 0 ∧ s' = 1) ∨ (s = 1 ∧ s' = 2) ∨ (s' = 0) at h
  rcases h with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | rfl
  · left; omega
  · left; omega
  · right; rfl

-- Test 4: abbrev + change at h + rcases (6 disjuncts)
abbrev MyRel6 (a b : Nat) : Prop :=
  (a = 0 ∧ b = 1) ∨ (a = 1 ∧ b = 2) ∨ (a = 2 ∧ b = 3) ∨
  (a = 3 ∧ b = 4) ∨ (a = 4 ∧ b = 5) ∨ (b = 0)

example (a b : Nat) (h : MyRel6 a b) :
    a ≤ b ∨ b = 0 := by
  change (a = 0 ∧ b = 1) ∨ (a = 1 ∧ b = 2) ∨ (a = 2 ∧ b = 3) ∨
         (a = 3 ∧ b = 4) ∨ (a = 4 ∧ b = 5) ∨ (b = 0) at h
  rcases h with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | rfl
  · left; omega
  · left; omega
  · left; omega
  · left; omega
  · left; omega
  · right; rfl
