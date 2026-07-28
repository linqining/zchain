import Mathlib

namespace ZmodTest

def P : Nat := 2^31 - 1

theorem P_prime : Nat.Prime P := by unfold P; native_decide
lemma P_gt_one : 1 < P := by unfold P; norm_num
lemma P_pos : 0 < P := by unfold P; norm_num

def M31 : Type := { n : Nat // n < P } deriving Repr

namespace M31

def zero : M31 := ⟨0, by unfold P; norm_num⟩
def one : M31 := ⟨1, by unfold P; norm_num⟩

def add (a b : M31) : M31 :=
  if h : a.val + b.val < P then
    ⟨a.val + b.val, h⟩
  else
    ⟨a.val + b.val - P, by
      have hlt : a.val + b.val < P + P := by linarith [a.property, b.property]
      omega⟩

def sub (a b : M31) : M31 :=
  if h : a.val ≥ b.val then
    ⟨a.val - b.val, by
      have ha : a.val < P := a.property
      have hdiff : a.val - b.val < P := by omega
      exact hdiff⟩
  else
    ⟨P - (b.val - a.val), by
      have hb : b.val < P := b.property
      have hdiff : b.val - a.val < P := by omega
      omega⟩

def mul (a b : M31) : M31 :=
  ⟨(a.val * b.val) % P, by
    have hlt : (a.val * b.val) % P < P := by
      apply Nat.mod_lt
      exact P_pos
    exact hlt⟩

def ne (a b : M31) : Bool := a.val ≠ b.val

lemma zero_val : (zero : M31).val = 0 := by simp [zero]
lemma one_val : (one : M31).val = 1 := by simp [one]

-- Test 1: dif_pos for sub_one_val_of_pos
lemma sub_one_val_of_pos (x : M31) (hx : 1 ≤ x.val) : (sub x one).val = x.val - 1 := by
  have h1 : (one : M31).val = 1 := one_val
  have hge : x.val ≥ 1 := hx
  simp only [sub, h1, dif_pos hge]

-- Test 2: Bool ne conversion via contradiction
example (a : M31) (ha : ne a zero = true) : a.val ≠ 0 := by
  intro hz
  have h_eq : a = zero := Subtype.ext (by rw [zero_val]; exact hz)
  rw [h_eq] at ha
  simp [ne, zero] at ha

-- Test 3: ZMod approach for mul_inv_exists
example (a : M31) (ha : ne a zero) : ∃ b : M31, mul a b = one := by
  have ha_val : a.val ≠ 0 := by
    intro hz
    have h_eq : a = zero := Subtype.ext (by rw [zero_val]; exact hz)
    rw [h_eq] at ha
    simp [ne, zero] at ha
  have ha_lt : a.val < P := a.property
  have ha_pos : 0 < a.val := by omega
  haveI : Fact (Nat.Prime P) := ⟨P_prime⟩
  have hza : (a.val : ZMod P) ≠ 0 := by
    intro hz
    rw [ZMod.natCast_zmod_eq_zero_iff_dvd] at hz
    obtain ⟨k, hk⟩ := hz
    have hk0 : k = 0 := by
      by_contra hnk
      have hk1 : 1 ≤ k := by omega
      have hmk : P ≤ P * k := Nat.mul_le_mul_left P hk1
      have hpa : P ≤ a.val := by rw [hk]; exact hmk
      omega
    rw [hk0, Nat.mul_zero] at hk
    exact ha_val hk
  have hinv : (a.val : ZMod P) * (a.val : ZMod P)⁻¹ = 1 := mul_inv_cancel₀ hza
  have hb_lt : ((a.val : ZMod P)⁻¹).val < P := (a.val : ZMod P)⁻¹.val_lt
  refine ⟨⟨((a.val : ZMod P)⁻¹).val, hb_lt⟩, ?_⟩
  apply Subtype.ext
  show (a.val * ((a.val : ZMod P)⁻¹).val) % P = (one : M31).val
  rw [one_val]
  have hmod : (a.val * ((a.val : ZMod P)⁻¹).val) % P = 1 := by
    have h1 : ((a.val * ((a.val : ZMod P)⁻¹).val : Nat) : ZMod P) = ((1 : Nat) : ZMod P) := by
      rw [Nat.cast_mul, ZMod.natCast_zmod_val, hinv, Nat.cast_one]
    rw [ZMod.natCast_eq_natCast_iff] at h1
    change (a.val * ((a.val : ZMod P)⁻¹).val) % P = 1 % P at h1
    rw [Nat.mod_eq_of_lt P_gt_one] at h1
    exact h1
  exact hmod

end M31
end ZmodTest
