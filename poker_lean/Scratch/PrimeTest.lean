import Mathlib

#check Nat.gcd_comm
#check Nat.Coprime.symm
#check Nat.coprime_comm
#check Int.ofNat_emod
#check Nat.intCast_emod
#check Nat.cast_emod
#check Subtype.ext
#check Nat.mul_le_mul_left
#check Nat.mul_one
#check Nat.mul_zero
#check Nat.coprime_of_lt_prime
example : (1 : Int) < ↑(2^31 - 1) := by unfold Nat.pow; omega
