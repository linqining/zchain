import Mathlib

namespace PokerLean

def M31_P : Nat := 2^31 - 1

theorem M31_P_pos : 0 < M31_P := by
  unfold M31_P
  norm_num

def M31 : Type := { n : Nat // n < M31_P } deriving Repr

namespace M31

def ofNat (n : Nat) (h : n < M31_P) : M31 := ⟨n, h⟩
def toNat (x : M31) : Nat := x.val

def zero : M31 := ⟨0, by unfold M31_P; norm_num⟩
def one : M31 := ⟨1, by unfold M31_P; norm_num⟩
def two : M31 := ⟨2, by unfold M31_P; norm_num⟩

def add (a b : M31) : M31 :=
  if h : a.val + b.val < M31_P then
    ⟨a.val + b.val, h⟩
  else
    ⟨a.val + b.val - M31_P, by
      have hlt : a.val + b.val < M31_P + M31_P := by linarith [a.property, b.property]
      omega⟩

def sub (a b : M31) : M31 :=
  if h : a.val ≥ b.val then
    ⟨a.val - b.val, by
      have ha : a.val < M31_P := a.property
      have hdiff : a.val - b.val < M31_P := by omega
      exact hdiff⟩
  else
    ⟨M31_P - (b.val - a.val), by
      have hb : b.val < M31_P := b.property
      have hdiff : b.val - a.val < M31_P := by omega
      omega⟩

def mul (a b : M31) : M31 :=
  ⟨(a.val * b.val) % M31_P, by
    have hlt : (a.val * b.val) % M31_P < M31_P := by
      apply Nat.mod_lt
      exact M31_P_pos
    exact hlt⟩

lemma mul_comm (a b : M31) : mul a b = mul b a := by
  apply Subtype.ext
  simp [mul, Nat.mul_comm]

lemma mul_zero_y (y : M31) : mul zero y = zero := by
  simp [mul, zero, Nat.mul_zero, Nat.zero_mod]

lemma mul_zero_left (a : M31) : mul zero a = zero := by
  exact mul_zero_y a

lemma mul_zero_right (a : M31) : mul a zero = zero := by
  simp [mul, zero, Nat.mul_zero, Nat.zero_mod]

def eq (a b : M31) : Bool := a.val = b.val
def ne (a b : M31) : Bool := a.val ≠ b.val

lemma zero_ne_one : zero ≠ one := by
  intro h
  have hv : zero.val = one.val := by exact congr_arg Subtype.val h
  simp [zero, one] at hv

axiom binality_sound (x : M31)
    (h : mul x (sub x one) = zero) :
  x = zero ∨ x = one

axiom binality_complete (x : M31)
    (h : x = zero ∨ x = one) :
  mul x (sub x one) = zero

axiom mul_inv_exists (a : M31) (ha : ne a zero) :
  ∃ b : M31, mul a b = one

end M31

end PokerLean