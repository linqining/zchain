import PokerLean.Common.M31

/-!
# u64 ↔ 4×M31 编码

将 u64 编码为 4 个 M31 limb（每 limb 16 位），
与 `poker_texas_air/src/airs/common.rs` 中的 `u64_to_m31_limbs` 一致。

## 公理消除状态

本文件中的所有原公理已转换为定理：
- `m31_add_no_overflow`：定理，需 limb 范围前置条件（< 65536）
- `limb_lt_65536`：定理，由 `u64ToLimbs` 定义直接推出
- `u64ToLimbs_correct`：定理，由 `u64ToLimbs` 定义直接推出
- `limbsToU64_bound`：定理，需 limb 范围前置条件
- `roundtrip`：定理，由上述定理组合推出

剩余的 state-root 信任边界是两个未解释函数：Poseidon 哈希与表状态编码，
位于 `PoseidonHash.lean` 和 `Types.lean`，不属于本文件。项目不再假设
Poseidon 在任意长度输入上的精确单射性。
-/

namespace PokerLean

/-! u64 类型表示（Lean 中用 Nat + 约束 < 2^64 表示） -/
def U64 : Type := { n : Nat // n < 2^64 }

namespace U64

def ofNat (n : Nat) (h : n < 2^64) : U64 := ⟨n, h⟩
def toNat (x : U64) : Nat := x.val

end U64

/-! ## Limb 范围约束（16-bit）

Rust AIR 通过独立的 range constraint 保证每 limb < 65536（16-bit）。
Lean 模型通过 `LimbRange16` / `Limb4Range16` 谓词抽象此约束。
两个 16-bit limb 之和 < 131072 < M31_P = 2^31 - 1，因此 M31.add 不取模。
-/

/-- 单个 limb 的 16-bit 范围约束：值 < 65536 = 2^16。 -/
def LimbRange16 (a : M31) : Prop := a.val < 65536

/-- 4-tuple limb 的 16-bit 范围约束：所有 4 个 limb 均 < 65536。 -/
def Limb4Range16 (a : M31 × M31 × M31 × M31) : Prop :=
  LimbRange16 a.1 ∧ LimbRange16 a.2.1 ∧ LimbRange16 a.2.2.1 ∧ LimbRange16 a.2.2.2

/-! 将 u64 分解为 4 个 16-bit limb（M31 域元素） -/
def u64ToLimbs (v : U64) : M31 × M31 × M31 × M31 :=
  let v' := v.val
  let l0 : Nat := v' % 65536
  let l1 : Nat := (v' / 65536) % 65536
  let l2 : Nat := (v' / (65536 * 65536)) % 65536
  let l3 : Nat := (v' / (65536 * 65536 * 65536)) % 65536
  have hl0 : l0 < M31_P := by
    apply Nat.lt_of_lt_of_le (Nat.mod_lt v' (by norm_num : (0 : Nat) < 65536))
    have h : (65536 : Nat) ≤ M31_P := by unfold M31_P; norm_num
    exact h
  have hl1 : l1 < M31_P := by
    apply Nat.lt_of_lt_of_le (Nat.mod_lt (v' / 65536) (by norm_num : (0 : Nat) < 65536))
    have h : (65536 : Nat) ≤ M31_P := by unfold M31_P; norm_num
    exact h
  have hl2 : l2 < M31_P := by
    apply Nat.lt_of_lt_of_le (Nat.mod_lt (v' / (65536 * 65536)) (by norm_num : (0 : Nat) < 65536))
    have h : (65536 : Nat) ≤ M31_P := by unfold M31_P; norm_num
    exact h
  have hl3 : l3 < M31_P := by
    apply Nat.lt_of_lt_of_le (Nat.mod_lt (v' / (65536 * 65536 * 65536)) (by norm_num : (0 : Nat) < 65536))
    have h : (65536 : Nat) ≤ M31_P := by unfold M31_P; norm_num
    exact h
  ⟨⟨l0, hl0⟩, ⟨l1, hl1⟩, ⟨l2, hl2⟩, ⟨l3, hl3⟩⟩

/-! ## 从定义直接证明的定理 -/

/-- `u64ToLimbs` 的各 limb 的 `.val` 等于对应的模运算结果。
    由 `u64ToLimbs` 的定义直接推出（`rfl`）。 -/
theorem u64ToLimbs_correct (v : U64) :
    (u64ToLimbs v).1.val = v.val % 65536 ∧
    (u64ToLimbs v).2.1.val = (v.val / 65536) % 65536 ∧
    (u64ToLimbs v).2.2.1.val = (v.val / (65536 * 65536)) % 65536 ∧
    (u64ToLimbs v).2.2.2.val = (v.val / (65536 * 65536 * 65536)) % 65536 := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · rfl
  · rfl
  · rfl
  · rfl

/-- 每个 limb < 65536。由 `u64ToLimbs_correct` + `Nat.mod_lt` 推出。 -/
theorem limb_lt_65536 (v : U64) : Limb4Range16 (u64ToLimbs v) := by
  obtain ⟨h0, h1, h2, h3⟩ := u64ToLimbs_correct v
  -- 展开 Limb4Range16 和 LimbRange16 定义
  simp only [Limb4Range16, LimbRange16]
  refine ⟨?_, ?_, ?_, ?_⟩
  · rw [h0]; exact Nat.mod_lt _ (by norm_num)
  · rw [h1]; exact Nat.mod_lt _ (by norm_num)
  · rw [h2]; exact Nat.mod_lt _ (by norm_num)
  · rw [h3]; exact Nat.mod_lt _ (by norm_num)

/-- 所有 limb 都 < M31_P -/
theorem limb_valid (v : U64) :
    let ⟨l0, l1, l2, l3⟩ := u64ToLimbs v
    l0.val < M31_P ∧ l1.val < M31_P ∧ l2.val < M31_P ∧ l3.val < M31_P := by
  simp only [u64ToLimbs]
  exact ⟨(u64ToLimbs v).1.property,
          (u64ToLimbs v).2.1.property,
          (u64ToLimbs v).2.2.1.property,
          (u64ToLimbs v).2.2.2.property⟩

/-! ## limbsToU64 与 roundtrip -/

/-- 当所有 limb < 65536 时，limbsToU64 的结果 < 2^64。
    证明思路：4 个 16-bit limb 的最大值为 65535，组合后最大为
    65535 + 65535 * 65536 + 65535 * 65536² + 65535 * 65536³ = 65536⁴ - 1 = 2⁶⁴ - 1 < 2⁶⁴。 -/
theorem limbsToU64_bound (l0 l1 l2 l3 : M31)
    (h0 : LimbRange16 l0) (h1 : LimbRange16 l1) (h2 : LimbRange16 l2) (h3 : LimbRange16 l3) :
    l0.val + l1.val * 65536 + l2.val * (65536 * 65536) + l3.val * (65536 * 65536 * 65536) < 2^64 := by
  -- 展开 LimbRange16 定义，使 omega 可见各 limb < 65536
  simp only [LimbRange16] at h0 h1 h2 h3
  -- 每个 limb ≤ 65535
  have hl0 : l0.val ≤ 65535 := by omega
  have hl1 : l1.val ≤ 65535 := by omega
  have hl2 : l2.val ≤ 65535 := by omega
  have hl3 : l3.val ≤ 65535 := by omega
  -- 4 个 16-bit limb 的最大组合 = 65536^4 - 1 = 2^64 - 1 < 2^64
  -- omega 处理线性（常数系数）不等式
  omega

/-- 从 4 个 M31 limb 重建 u64（需要 limb 范围约束保证结果 < 2^64）。 -/
def limbsToU64 (l0 l1 l2 l3 : M31)
    (h0 : LimbRange16 l0) (h1 : LimbRange16 l1) (h2 : LimbRange16 l2) (h3 : LimbRange16 l3) : U64 :=
  let v := l0.val + l1.val * 65536 + l2.val * (65536 * 65536) + l3.val * (65536 * 65536 * 65536)
  ⟨v, limbsToU64_bound l0 l1 l2 l3 h0 h1 h2 h3⟩

/-- 往返一致性：u64ToLimbs 后 limbsToU64 还原原值。 -/
theorem roundtrip (v : U64) :
    limbsToU64 (u64ToLimbs v).1 (u64ToLimbs v).2.1 (u64ToLimbs v).2.2.1 (u64ToLimbs v).2.2.2
      (limb_lt_65536 v).1 (limb_lt_65536 v).2.1 (limb_lt_65536 v).2.2.1 (limb_lt_65536 v).2.2.2
    = v := by
  apply Subtype.ext
  -- 展开 limbsToU64 和 u64ToLimbs
  show (u64ToLimbs v).1.val + (u64ToLimbs v).2.1.val * 65536 +
        (u64ToLimbs v).2.2.1.val * (65536 * 65536) +
        (u64ToLimbs v).2.2.2.val * (65536 * 65536 * 65536) = v.val
  -- 使用 u64ToLimbs_correct 展开 limb 值
  have hc := u64ToLimbs_correct v
  rw [hc.1, hc.2.1, hc.2.2.1, hc.2.2.2]
  -- 目标：v.val % 65536 + (v.val / 65536) % 65536 * 65536 + ... = v.val
  -- 这是 4×16-bit limb 分解的正确性，需 v.val < 65536^4 = 2^64 保证顶层商 < 65536
  have hv : v.val < 2^64 := v.property
  -- omega 处理 Nat.div/Nat.mod 分解与边界推理
  omega

/-! u64 解码辅助函数 -/
def decodeU64 (l0 l1 l2 l3 : M31) : Nat :=
  l0.val + l1.val * 65536 + l2.val * (65536 * 65536) + l3.val * (65536 * 65536 * 65536)

/-! Nat 到 M31 的简单转换（需要证明 n < M31_P） -/
def natToM31 (n : Nat) (h : n < M31_P) : M31 := ⟨n, h⟩

/-! 常量 -/
def U64_MAX : Nat := 2^64
def LIMB_SIZE : Nat := 65536

/-! ## Limb 加法无溢出定理

Rust AIR 通过独立的 range constraint 保证每 limb < 65536（16-bit），
因此两个 limb 之和 < 131072 < M31_P = 2^31 - 1，M31.add 不取模。
Lean 模型通过 `LimbRange16` 谓词抽象 range constraint。
-/

/-- 定理：当两个 limb 都 < 65536 时，M31.add 不溢出（和 < 131072 < M31_P）。
    原 `m31_add_no_overflow` 公理已消除，转换为带前置条件的定理。 -/
theorem m31_add_no_overflow (a b : M31) (ha : LimbRange16 a) (hb : LimbRange16 b) :
    (M31.add a b).val = a.val + b.val := by
  -- 展开 LimbRange16 定义，使 omega 可见 a.val < 65536, b.val < 65536
  simp only [LimbRange16] at ha hb
  -- 两 limb 之和 < 65536 + 65536 = 131072 < 2^31 - 1 = M31_P
  have h_lt : a.val + b.val < M31_P := by unfold M31_P; omega
  -- M31.add 的定义：if h : a.val + b.val < M31_P then ⟨a.val + b.val, h⟩ else ...
  -- 使用 dif_pos（依赖 if）选择 then 分支
  simp only [M31.add, dif_pos h_lt]

/-- 引理：逐 limb M31.add 保持 decodeU64 线性。
    需要 `Limb4Range16` 前置条件（pre 和 amt 的所有 limb < 65536）。
    原 `decodeU64_limb_add` 公理已消除，转换为带前置条件的引理。 -/
lemma decodeU64_limb_add (a b : M31 × M31 × M31 × M31)
    (ha : Limb4Range16 a) (hb : Limb4Range16 b) :
    decodeU64 (M31.add a.1 b.1) (M31.add a.2.1 b.2.1) (M31.add a.2.2.1 b.2.2.1) (M31.add a.2.2.2 b.2.2.2)
    = decodeU64 a.1 a.2.1 a.2.2.1 a.2.2.2 + decodeU64 b.1 b.2.1 b.2.2.1 b.2.2.2 := by
  rcases ha with ⟨ha0, ha1, ha2, ha3⟩
  rcases hb with ⟨hb0, hb1, hb2, hb3⟩
  -- 使用 m31_add_no_overflow 展开每个 M31.add
  simp only [decodeU64,
    m31_add_no_overflow a.1 b.1 ha0 hb0,
    m31_add_no_overflow a.2.1 b.2.1 ha1 hb1,
    m31_add_no_overflow a.2.2.1 b.2.2.1 ha2 hb2,
    m31_add_no_overflow a.2.2.2 b.2.2.2 ha3 hb3]
  -- 剩余为纯 Nat 算术，由 ring 消化
  ring

end PokerLean
