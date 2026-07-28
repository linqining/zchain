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

/-! ## 素性：M31_P = 2^31 - 1 是梅森素数

`2^31 - 1 = 2147483647` 是第 8 个梅森素数。通过 `native_decide`（编译原生代码
运行判定过程）证明，仅依赖 Lean 标准基础公理（`propext`、`Classical.choice`、
`Quot.sound`）与 `Lean.ofReduceBool`（native 计算信任，等价于机器验证素性），
而非自定义公理。
-/

theorem M31_P_prime : Nat.Prime M31_P := by
  unfold M31_P
  native_decide

/-- `1 < M31_P`，供模运算引理使用。 -/
lemma M31_P_gt_one : 1 < M31_P := by unfold M31_P; norm_num

/-! ## 二值性：x·(x-1) = 0 ↔ x ∈ {0, 1}

由 M31_P 素性推出 M31 是整环（无零因子）。
-/

/-- 二值性（完备方向）：x ∈ {0,1} ⇒ x·(x-1) = 0。无需素性。 -/
theorem binality_complete (x : M31)
    (h : x = zero ∨ x = one) :
  mul x (sub x one) = zero := by
  rcases h with rfl | rfl
  · -- x = zero：mul zero (sub zero one) = zero（左零元）
    exact mul_zero_left (sub zero one)
  · -- x = one：sub one one = zero，mul one zero = zero（右零元）
    have h_sub : sub one one = zero := by
      apply Subtype.ext
      simp [sub, one, zero, M31_P]
    rw [h_sub]
    exact mul_zero_right one

/-- `one.val = 1`。 -/
lemma one_val : (one : M31).val = 1 := by simp [one]

/-- `zero.val = 0`。 -/
lemma zero_val : (zero : M31).val = 0 := by simp [zero]

/-- 当 x.val ≥ 1 时，`(sub x one).val = x.val - 1`。
    使用 `dif_pos` 而非 `if_pos`，因为 `sub` 的 `if h : ...` 是依赖类型 if（dite）。 -/
lemma sub_one_val_of_pos (x : M31) (hx : 1 ≤ x.val) : (sub x one).val = x.val - 1 := by
  have h1 : (one : M31).val = 1 := one_val
  have hge : x.val ≥ 1 := hx
  simp only [sub, h1, dif_pos hge]

/-- 二值性（可靠方向）：x·(x-1) = 0 ⇒ x ∈ {0,1}。
    依赖 M31_P 素性（整环 ⇒ 无零因子 ⇒ Euclid 引理）。 -/
theorem binality_sound (x : M31)
    (h : mul x (sub x one) = zero) :
  x = zero ∨ x = one := by
  -- 情形 1：x.val = 0 ⇒ x = zero
  by_cases hx0 : x.val = 0
  · left
    apply Subtype.ext
    rw [zero_val]; exact hx0
  -- 情形 2：x.val ≥ 1
  · right
    have hx1 : 1 ≤ x.val := by omega
    have hx_lt : x.val < M31_P := x.property
    -- (sub x one).val = x.val - 1
    have h_sub : (sub x one).val = x.val - 1 := sub_one_val_of_pos x hx1
    -- mul x (sub x one) = zero ⇒ (x.val * (x.val - 1)) % M31_P = 0
    have h_mod : (x.val * (x.val - 1)) % M31_P = 0 := by
      have h1 : (mul x (sub x one)).val = zero.val := by rw [h]
      simp only [mul, zero_val, h_sub] at h1
      exact h1
    -- M31_P ∣ x.val * (x.val - 1)
    have h_dvd : M31_P ∣ x.val * (x.val - 1) :=
      Nat.dvd_iff_mod_eq_zero.mpr h_mod
    -- Euclid 引理：M31_P 素 ⇒ M31_P ∣ x.val 或 M31_P ∣ (x.val - 1)
    have h_euclid : M31_P ∣ x.val ∨ M31_P ∣ (x.val - 1) :=
      (Nat.Prime.dvd_mul M31_P_prime).mp h_dvd
    -- x.val ≥ 1 且 x.val < M31_P ⇒ M31_P ∤ x.val
    have h_not_dvd_x : ¬(M31_P ∣ x.val) := by
      rintro ⟨k, hk⟩
      -- hk : x.val = M31_P * k
      have hk0 : k = 0 := by
        by_contra hnk
        have hk1 : 1 ≤ k := by omega
        have hmk : M31_P ≤ M31_P * k := by
          have hh := Nat.mul_le_mul_left M31_P hk1
          rwa [Nat.mul_one] at hh
        omega
      rw [hk0, Nat.mul_zero] at hk
      omega
    -- 故 M31_P ∣ (x.val - 1)，且 0 ≤ x.val - 1 < M31_P ⇒ x.val - 1 = 0
    have h_dvd_sub : M31_P ∣ (x.val - 1) := h_euclid.resolve_left h_not_dvd_x
    have h_sub_eq_zero : x.val - 1 = 0 := by
      obtain ⟨k, hk⟩ := h_dvd_sub
      -- hk : x.val - 1 = M31_P * k
      by_cases hk0 : k = 0
      · rw [hk0, Nat.mul_zero] at hk; omega
      · have hk1 : 1 ≤ k := by omega
        have hmk : M31_P ≤ M31_P * k := by
          have hh := Nat.mul_le_mul_left M31_P hk1
          rwa [Nat.mul_one] at hh
        have h_sub_lt : x.val - 1 < M31_P := by omega
        omega
    apply Subtype.ext
    show x.val = (one : M31).val
    rw [one_val]
    omega

/-- 乘法逆元存在性：M31_P 素 ⇒ 每个非零元素有乘法逆元。
    利用 `ZMod M31_P` 的 Field 结构（由 `Fact (Nat.Prime M31_P)` 提供）。 -/
theorem mul_inv_exists (a : M31) (ha : ne a zero) :
  ∃ b : M31, mul a b = one := by
  -- 将 `ne a zero = true` (Bool) 转换为 `a.val ≠ 0` (Prop)
  have ha_val : a.val ≠ 0 := by
    intro hz
    -- hz : a.val = 0 ⇒ a = zero ⇒ zero.ne zero = true ⇒ false = true
    have h_eq : a = zero := Subtype.ext (by rw [zero_val]; exact hz)
    rw [h_eq] at ha
    -- ha : zero.ne zero = true，展开后为 decide (zero.val ≠ zero.val) = true，矛盾
    simp [ne, zero] at ha
  have ha_lt : a.val < M31_P := a.property
  -- 提供 Fact (Nat.Prime M31_P) 使 ZMod M31_P 成为 Field
  haveI : Fact (Nat.Prime M31_P) := ⟨M31_P_prime⟩
  -- (a.val : ZMod M31_P) ≠ 0
  have hza : (a.val : ZMod M31_P) ≠ 0 := by
    intro hz
    -- hz : (a.val : ZMod M31_P) = 0 ⇒ M31_P ∣ a.val
    rw [ZMod.natCast_zmod_eq_zero_iff_dvd] at hz
    obtain ⟨k, hk⟩ := hz
    -- hk : a.val = M31_P * k；但 0 < a.val < M31_P ⇒ k = 0 ⇒ a.val = 0，矛盾
    have hk0 : k = 0 := by
      by_contra hnk
      have hk1 : 1 ≤ k := by omega
      have hmk : M31_P ≤ M31_P * k := Nat.mul_le_mul_left M31_P hk1
      have hpa : M31_P ≤ a.val := by rw [hk]; exact hmk
      omega
    rw [hk0, Nat.mul_zero] at hk
    exact ha_val hk
  -- ZMod 是 Field，逆元存在：a * a⁻¹ = 1
  have hinv : (a.val : ZMod M31_P) * (a.val : ZMod M31_P)⁻¹ = 1 := mul_inv_cancel₀ hza
  -- 逆元的 val < M31_P
  have hb_lt : ((a.val : ZMod M31_P)⁻¹).val < M31_P := (a.val : ZMod M31_P)⁻¹.val_lt
  refine ⟨⟨((a.val : ZMod M31_P)⁻¹).val, hb_lt⟩, ?_⟩
  apply Subtype.ext
  -- 目标：(a.val * b) % M31_P = (one : M31).val
  show (a.val * ((a.val : ZMod M31_P)⁻¹).val) % M31_P = (one : M31).val
  rw [one_val]
  -- 关键步骤：(a.val * b) % M31_P = 1
  have hmod : (a.val * ((a.val : ZMod M31_P)⁻¹).val) % M31_P = 1 := by
    -- 在 ZMod M31_P 中：a.val * b = 1
    have h1 : ((a.val * ((a.val : ZMod M31_P)⁻¹).val : Nat) : ZMod M31_P) = ((1 : Nat) : ZMod M31_P) := by
      rw [Nat.cast_mul, ZMod.natCast_zmod_val, hinv, Nat.cast_one]
    -- 转换为模等式：a.val * b ≡ 1 [MOD M31_P]
    rw [ZMod.natCast_eq_natCast_iff] at h1
    -- h1 : (a.val * b) % M31_P = 1 % M31_P；由 1 < M31_P，1 % M31_P = 1
    change (a.val * ((a.val : ZMod M31_P)⁻¹).val) % M31_P = 1 % M31_P at h1
    rw [Nat.mod_eq_of_lt M31_P_gt_one] at h1
    exact h1
  exact hmod

end M31

end PokerLean
