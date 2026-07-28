import Mathlib

import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.PoseidonHash
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.Funds
import PokerLean.AIR.AirBase
import PokerLean.AIR.FundsAir

namespace PokerLean

set_option linter.unusedVariables false in

/-! # 资金方法 AIR soundness（addon, rebuy）

## 历史背景

此前本文件包含两个"反例"（`addon_air_not_sound` / `rebuy_air_not_sound`），
通过向提取函数传入 `expected_seat_index + 1`（与 AIR 强制的 `expected_seat_index`
不一致）来构造 AIR 接受但合约拒绝的假象。这并非真实的 soundness 漏洞——
正确的 soundness 定理应使用与 AIR 一致的 `expected_seat_index` 进行状态提取。

## 当前结论

- `addon_air_sound`：addon AIR 在正确提取下满足 `ContractAddon`（4-limb 守恒 +
  addon_pool 守恒 + 版本递增 + 座位占用 + 金额 > 0）。
- `rebuy_air_sound`：rebuy AIR 在正确提取下满足 `ContractRebuy`（4-limb 守恒 +
  addon_pool 守恒 + 版本递增 + 座位占用 + 金额 > 0）。

## 已知限制

AIR 的逐 limb 加法约束（`post = M31.add pre amount`）在 M31 域内进行，
不显式强制 limb 进位传播。在 Rust 实现中，limb 范围约束（每 limb < 65536）
由独立的 range constraint 保证；Lean 模型暂未引入 range constraint，
因此下列证明假设 limb 不溢出（等价于 `decodeU64` 语义，
通过公理 `m31_add_no_overflow` 抽象）。 -/

/-! ## addon 辅助引理 -/

private lemma addon_pre_max_players
    (row : CommonRow) (ext : AddonMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromAddonAir row ext max_players seat_index).max_players = max_players := by
  simp [extractPreTableFromAddonAir, extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma addon_pre_version
    (row : CommonRow) (ext : AddonMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromAddonAir row ext max_players seat_index).version =
      decodeU64 row.pre_version.1 row.pre_version.2.1
        row.pre_version.2.2.1 row.pre_version.2.2.2 := by
  simp [extractPreTableFromAddonAir, extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma addon_pre_round_state
    (row : CommonRow) (ext : AddonMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromAddonAir row ext max_players seat_index).round_state =
      RoundState.fromNat row.pre_round_state.val := by
  simp [extractPreTableFromAddonAir, extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma addon_pre_addon_pool
    (row : CommonRow) (ext : AddonMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromAddonAir row ext max_players seat_index).addon_pool =
      decodeU64 ext.input_pre_addon_pool.1 ext.input_pre_addon_pool.2.1
        ext.input_pre_addon_pool.2.2.1 ext.input_pre_addon_pool.2.2.2 := by
  simp [extractPreTableFromAddonAir, extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma addon_pre_big_blind
    (row : CommonRow) (ext : AddonMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromAddonAir row ext max_players seat_index).big_blind = 0 := by
  simp [extractPreTableFromAddonAir, extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma addon_pre_small_blind
    (row : CommonRow) (ext : AddonMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromAddonAir row ext max_players seat_index).small_blind = 0 := by
  simp [extractPreTableFromAddonAir, extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma addon_pre_hand_id
    (row : CommonRow) (ext : AddonMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromAddonAir row ext max_players seat_index).hand_id = row.hand_id.val := by
  simp [extractPreTableFromAddonAir, extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma addon_post_version
    (row : CommonRow) (ext : AddonMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromAddonAir row ext max_players seat_index).version =
      decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2 := by
  simp [extractPostTableFromAddonAir, extractPreTableFromAddonAir,
         extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma addon_post_round_state
    (row : CommonRow) (ext : AddonMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromAddonAir row ext max_players seat_index).round_state =
      RoundState.fromNat row.post_round_state.val := by
  simp [extractPostTableFromAddonAir, extractPreTableFromAddonAir,
         extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma addon_post_addon_pool
    (row : CommonRow) (ext : AddonMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromAddonAir row ext max_players seat_index).addon_pool =
      decodeU64 ext.output_post_addon_pool.1 ext.output_post_addon_pool.2.1
        ext.output_post_addon_pool.2.2.1 ext.output_post_addon_pool.2.2.2 := by
  simp [extractPostTableFromAddonAir, extractPreTableFromAddonAir,
         extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma addon_post_max_players
    (row : CommonRow) (ext : AddonMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromAddonAir row ext max_players seat_index).max_players = max_players := by
  simp [extractPostTableFromAddonAir, extractPreTableFromAddonAir,
         extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma addon_post_big_blind
    (row : CommonRow) (ext : AddonMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromAddonAir row ext max_players seat_index).big_blind = 0 := by
  simp [extractPostTableFromAddonAir, extractPreTableFromAddonAir,
         extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma addon_post_small_blind
    (row : CommonRow) (ext : AddonMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromAddonAir row ext max_players seat_index).small_blind = 0 := by
  simp [extractPostTableFromAddonAir, extractPreTableFromAddonAir,
         extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma addon_post_hand_id
    (row : CommonRow) (ext : AddonMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromAddonAir row ext max_players seat_index).hand_id = row.hand_id.val := by
  simp [extractPostTableFromAddonAir, extractPreTableFromAddonAir,
         extractPreTableFromFundsAir, TexasPokerTable.update_seat]

/-! ### addon 座位访问引理 -/

private lemma addon_pre_get_seat_at_index
    (row : CommonRow) (ext : AddonMethodColumns) (max_players : Nat) (seat_index : Nat)
    (h_lt : seat_index < max_players) :
    (extractPreTableFromAddonAir row ext max_players seat_index).get_seat seat_index =
      { Seat.empty with
        player := PlayerId.ofNat 1,
        pending_addon := decodeU64 ext.pre_pending_addon.1 ext.pre_pending_addon.2.1
            ext.pre_pending_addon.2.2.1 ext.pre_pending_addon.2.2.2 } := by
  simp only [extractPreTableFromAddonAir, extractPreTableFromFundsAir,
             TexasPokerTable.get_seat, TexasPokerTable.update_seat,
             List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_eq, List.getElem?_replicate, h_lt, if_true,
             Option.map_some, Option.getD_some]

private lemma addon_pre_get_seat_other
    (row : CommonRow) (ext : AddonMethodColumns) (max_players : Nat) (seat_index : Nat)
    (i : Nat) (h_ne : i ≠ seat_index) (h_lt : i < max_players) :
    (extractPreTableFromAddonAir row ext max_players seat_index).get_seat i = Seat.empty := by
  have h_ne' : seat_index ≠ i := Ne.symm h_ne
  simp only [extractPreTableFromAddonAir, extractPreTableFromFundsAir,
             TexasPokerTable.get_seat, TexasPokerTable.update_seat,
             List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
             Option.getD_some]

private lemma addon_post_get_seat_at_index
    (row : CommonRow) (ext : AddonMethodColumns) (max_players : Nat) (seat_index : Nat)
    (h_lt : seat_index < max_players) :
    (extractPostTableFromAddonAir row ext max_players seat_index).get_seat seat_index =
      { Seat.empty with
        player := PlayerId.ofNat 1,
        pending_addon := decodeU64 ext.post_pending_addon.1 ext.post_pending_addon.2.1
            ext.post_pending_addon.2.2.1 ext.post_pending_addon.2.2.2 } := by
  simp only [extractPostTableFromAddonAir, extractPreTableFromAddonAir,
             extractPreTableFromFundsAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_eq, List.getElem?_replicate, h_lt, if_true,
             Option.map_some, Option.getD_some]

private lemma addon_post_get_seat_other
    (row : CommonRow) (ext : AddonMethodColumns) (max_players : Nat) (seat_index : Nat)
    (i : Nat) (h_ne : i ≠ seat_index) (h_lt : i < max_players) :
    (extractPostTableFromAddonAir row ext max_players seat_index).get_seat i =
      (extractPreTableFromAddonAir row ext max_players seat_index).get_seat i := by
  have h_ne' : seat_index ≠ i := Ne.symm h_ne
  simp only [extractPostTableFromAddonAir, extractPreTableFromAddonAir,
             extractPreTableFromFundsAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
             Option.getD_some]

private lemma addon_params_seat
    (ext : AddonMethodColumns) :
    (extractAddonParamsFromAir ext).seat_index = ext.input_seat_index.val := by
  simp [extractAddonParamsFromAir]

private lemma addon_params_amount
    (ext : AddonMethodColumns) :
    (extractAddonParamsFromAir ext).amount =
      decodeU64 ext.input_amount.1 ext.input_amount.2.1
        ext.input_amount.2.2.1 ext.input_amount.2.2.2 := by
  simp [extractAddonParamsFromAir]

/-! ### addon AIR soundness 主定理 -/

theorem addon_air_sound :
  ∀ (row : CommonRow) (ext : AddonMethodColumns)
    (expected_seat_index : Nat) (expected_amount : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hseat : expected_seat_index < max_players),
    AddonAirAcceptable row ext expected_seat_index expected_amount max_players hlt →
    -- Limb range constraints（由 Rust AIR 的独立 range constraint 保证）
    Limb4Range16 ext.pre_pending_addon →
    Limb4Range16 ext.input_amount →
    ContractAddon
      (extractPreTableFromAddonAir row ext max_players expected_seat_index)
      (extractAddonParamsFromAir ext)
      (extractPostTableFromAddonAir row ext max_players expected_seat_index) := by
  intro row ext expected_seat_index expected_amount max_players hlt hseat h_air
    h_range_pre h_range_amt
  -- 1. 解构 AIR 假设
  have h_active : row.is_active = M31.one := h_air.2.2.2
  have h_method : AddonMethodConstraints row ext expected_seat_index expected_amount
      max_players hlt := h_air.2.1
  -- 2. 应用 active 前提得到约束合取
  have h_c := h_method h_active
  rcases h_c with ⟨h_ver, h_rs_unch, h_seat_eq, _h_amt_eq, h_amt_pos,
                    _h_occ, h_pa0, h_pa1, h_pa2, h_pa3, h_addon_pool, _h_src⟩
  -- 3. 关键派生：seat_index 一致性
  have h_seat_val : ext.input_seat_index.val = expected_seat_index := by
    rw [h_seat_eq]; simp [nat_to_m31]
  have h_params_seat : (extractAddonParamsFromAir ext).seat_index = expected_seat_index := by
    rw [addon_params_seat, h_seat_val]
  have h_params_amount : (extractAddonParamsFromAir ext).amount =
      decodeU64 ext.input_amount.1 ext.input_amount.2.1
        ext.input_amount.2.2.1 ext.input_amount.2.2.2 := addon_params_amount ext
  -- 4. 约束前提展开（active 成立）
  have h_ver' : decodeU64 row.post_version.1 row.post_version.2.1
                  row.post_version.2.2.1 row.post_version.2.2.2 =
                decodeU64 row.pre_version.1 row.pre_version.2.1
                  row.pre_version.2.2.1 row.pre_version.2.2.2 + 1 := h_ver h_active
  have h_rs' : row.post_round_state = row.pre_round_state := h_rs_unch h_active
  -- 5. pending_addon 守恒（逐 limb → decodeU64 线性）
  have h_pending_addon_eq :
      decodeU64 ext.post_pending_addon.1 ext.post_pending_addon.2.1
        ext.post_pending_addon.2.2.1 ext.post_pending_addon.2.2.2 =
      decodeU64 ext.pre_pending_addon.1 ext.pre_pending_addon.2.1
        ext.pre_pending_addon.2.2.1 ext.pre_pending_addon.2.2.2 +
      decodeU64 ext.input_amount.1 ext.input_amount.2.1
        ext.input_amount.2.2.1 ext.input_amount.2.2.2 := by
    rw [h_pa0, h_pa1, h_pa2, h_pa3]
    exact decodeU64_limb_add ext.pre_pending_addon ext.input_amount
      h_range_pre h_range_amt
  -- 6. addon_pool 守恒
  have h_addon_pool' :
      decodeU64 ext.output_post_addon_pool.1 ext.output_post_addon_pool.2.1
        ext.output_post_addon_pool.2.2.1 ext.output_post_addon_pool.2.2.2 =
      decodeU64 ext.input_pre_addon_pool.1 ext.input_pre_addon_pool.2.1
        ext.input_pre_addon_pool.2.2.1 ext.input_pre_addon_pool.2.2.2 +
      decodeU64 ext.input_amount.1 ext.input_amount.2.1
        ext.input_amount.2.2.1 ext.input_amount.2.2.2 := h_addon_pool
  -- 7. 座位级引理
  have h_pre_seat : (extractPreTableFromAddonAir row ext max_players expected_seat_index).get_seat
      expected_seat_index =
      { Seat.empty with
        player := PlayerId.ofNat 1,
        pending_addon := decodeU64 ext.pre_pending_addon.1 ext.pre_pending_addon.2.1
            ext.pre_pending_addon.2.2.1 ext.pre_pending_addon.2.2.2 } :=
    addon_pre_get_seat_at_index row ext max_players expected_seat_index hseat
  have h_post_seat : (extractPostTableFromAddonAir row ext max_players expected_seat_index).get_seat
      expected_seat_index =
      { Seat.empty with
        player := PlayerId.ofNat 1,
        pending_addon := decodeU64 ext.post_pending_addon.1 ext.post_pending_addon.2.1
            ext.post_pending_addon.2.2.1 ext.post_pending_addon.2.2.2 } :=
    addon_post_get_seat_at_index row ext max_players expected_seat_index hseat
  -- 8. 证明 ContractAddon 的 12 个合取
  unfold ContractAddon
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · -- 1. params.seat_index < pre.max_players
    rw [h_params_seat, addon_pre_max_players]; exact hseat
  · -- 2. params.amount > 0
    rw [h_params_amount]; exact h_amt_pos
  · -- 3. (pre.get_seat params.seat_index).is_occupied = true
    rw [h_params_seat, h_pre_seat]
    simp [Seat.is_occupied, Seat.empty, EMPTY_PLAYER, PlayerId.ofNat]
  · -- 4. (post.get_seat ...).pending_addon = (pre.get_seat ...).pending_addon + params.amount
    rw [h_params_seat, h_post_seat, h_pre_seat, h_params_amount]
    exact h_pending_addon_eq
  · -- 5. post.addon_pool = pre.addon_pool + params.amount
    rw [addon_post_addon_pool, addon_pre_addon_pool, h_params_amount]
    exact h_addon_pool'
  · -- 6. post.version = pre.version + 1
    rw [addon_post_version, addon_pre_version]; exact h_ver'
  · -- 7. ∀ i, i ≠ params.seat_index → i < pre.max_players → post.get_seat i = pre.get_seat i
    intro i h_ne h_lt
    rw [h_params_seat] at h_ne
    rw [addon_pre_max_players] at h_lt
    exact addon_post_get_seat_other row ext max_players expected_seat_index i h_ne h_lt
  · -- 8. post.round_state = pre.round_state
    rw [addon_post_round_state, addon_pre_round_state, h_rs']
  · -- 9. post.max_players = pre.max_players
    exact addon_post_max_players row ext max_players expected_seat_index
  · -- 10. post.big_blind = pre.big_blind
    rw [addon_post_big_blind, addon_pre_big_blind]
  · -- 11. post.small_blind = pre.small_blind
    rw [addon_post_small_blind, addon_pre_small_blind]
  · -- 12. post.hand_id = pre.hand_id
    rw [addon_post_hand_id, addon_pre_hand_id]

/-! ## rebuy 辅助引理 -/

private lemma rebuy_pre_max_players
    (row : CommonRow) (ext : RebuyMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromRebuyAir row ext max_players seat_index).max_players = max_players := by
  simp [extractPreTableFromRebuyAir, extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma rebuy_pre_version
    (row : CommonRow) (ext : RebuyMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromRebuyAir row ext max_players seat_index).version =
      decodeU64 row.pre_version.1 row.pre_version.2.1
        row.pre_version.2.2.1 row.pre_version.2.2.2 := by
  simp [extractPreTableFromRebuyAir, extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma rebuy_pre_round_state
    (row : CommonRow) (ext : RebuyMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromRebuyAir row ext max_players seat_index).round_state =
      RoundState.fromNat row.pre_round_state.val := by
  simp [extractPreTableFromRebuyAir, extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma rebuy_pre_addon_pool
    (row : CommonRow) (ext : RebuyMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromRebuyAir row ext max_players seat_index).addon_pool =
      decodeU64 ext.input_pre_addon_pool.1 ext.input_pre_addon_pool.2.1
        ext.input_pre_addon_pool.2.2.1 ext.input_pre_addon_pool.2.2.2 := by
  simp [extractPreTableFromRebuyAir, extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma rebuy_pre_big_blind
    (row : CommonRow) (ext : RebuyMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromRebuyAir row ext max_players seat_index).big_blind = 0 := by
  simp [extractPreTableFromRebuyAir, extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma rebuy_pre_small_blind
    (row : CommonRow) (ext : RebuyMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromRebuyAir row ext max_players seat_index).small_blind = 0 := by
  simp [extractPreTableFromRebuyAir, extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma rebuy_pre_hand_id
    (row : CommonRow) (ext : RebuyMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPreTableFromRebuyAir row ext max_players seat_index).hand_id = row.hand_id.val := by
  simp [extractPreTableFromRebuyAir, extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma rebuy_post_version
    (row : CommonRow) (ext : RebuyMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromRebuyAir row ext max_players seat_index).version =
      decodeU64 row.post_version.1 row.post_version.2.1
        row.post_version.2.2.1 row.post_version.2.2.2 := by
  simp [extractPostTableFromRebuyAir, extractPreTableFromRebuyAir,
         extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma rebuy_post_round_state
    (row : CommonRow) (ext : RebuyMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromRebuyAir row ext max_players seat_index).round_state =
      RoundState.fromNat row.post_round_state.val := by
  simp [extractPostTableFromRebuyAir, extractPreTableFromRebuyAir,
         extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma rebuy_post_addon_pool
    (row : CommonRow) (ext : RebuyMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromRebuyAir row ext max_players seat_index).addon_pool =
      decodeU64 ext.output_post_addon_pool.1 ext.output_post_addon_pool.2.1
        ext.output_post_addon_pool.2.2.1 ext.output_post_addon_pool.2.2.2 := by
  simp [extractPostTableFromRebuyAir, extractPreTableFromRebuyAir,
         extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma rebuy_post_max_players
    (row : CommonRow) (ext : RebuyMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromRebuyAir row ext max_players seat_index).max_players = max_players := by
  simp [extractPostTableFromRebuyAir, extractPreTableFromRebuyAir,
         extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma rebuy_post_big_blind
    (row : CommonRow) (ext : RebuyMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromRebuyAir row ext max_players seat_index).big_blind = 0 := by
  simp [extractPostTableFromRebuyAir, extractPreTableFromRebuyAir,
         extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma rebuy_post_small_blind
    (row : CommonRow) (ext : RebuyMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromRebuyAir row ext max_players seat_index).small_blind = 0 := by
  simp [extractPostTableFromRebuyAir, extractPreTableFromRebuyAir,
         extractPreTableFromFundsAir, TexasPokerTable.update_seat]

private lemma rebuy_post_hand_id
    (row : CommonRow) (ext : RebuyMethodColumns) (max_players : Nat) (seat_index : Nat) :
    (extractPostTableFromRebuyAir row ext max_players seat_index).hand_id = row.hand_id.val := by
  simp [extractPostTableFromRebuyAir, extractPreTableFromRebuyAir,
         extractPreTableFromFundsAir, TexasPokerTable.update_seat]

/-! ### rebuy 座位访问引理 -/

private lemma rebuy_pre_get_seat_at_index
    (row : CommonRow) (ext : RebuyMethodColumns) (max_players : Nat) (seat_index : Nat)
    (h_lt : seat_index < max_players) :
    (extractPreTableFromRebuyAir row ext max_players seat_index).get_seat seat_index =
      { Seat.empty with
        player := PlayerId.ofNat 1,
        stack := decodeU64 ext.pre_stack.1 ext.pre_stack.2.1
            ext.pre_stack.2.2.1 ext.pre_stack.2.2.2 } := by
  simp only [extractPreTableFromRebuyAir, extractPreTableFromFundsAir,
             TexasPokerTable.get_seat, TexasPokerTable.update_seat,
             List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_eq, List.getElem?_replicate, h_lt, if_true,
             Option.map_some, Option.getD_some]

private lemma rebuy_pre_get_seat_other
    (row : CommonRow) (ext : RebuyMethodColumns) (max_players : Nat) (seat_index : Nat)
    (i : Nat) (h_ne : i ≠ seat_index) (h_lt : i < max_players) :
    (extractPreTableFromRebuyAir row ext max_players seat_index).get_seat i = Seat.empty := by
  have h_ne' : seat_index ≠ i := Ne.symm h_ne
  simp only [extractPreTableFromRebuyAir, extractPreTableFromFundsAir,
             TexasPokerTable.get_seat, TexasPokerTable.update_seat,
             List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
             Option.getD_some]

private lemma rebuy_post_get_seat_at_index
    (row : CommonRow) (ext : RebuyMethodColumns) (max_players : Nat) (seat_index : Nat)
    (h_lt : seat_index < max_players) :
    (extractPostTableFromRebuyAir row ext max_players seat_index).get_seat seat_index =
      { Seat.empty with
        player := PlayerId.ofNat 1,
        stack := decodeU64 ext.post_stack.1 ext.post_stack.2.1
            ext.post_stack.2.2.1 ext.post_stack.2.2.2 } := by
  simp only [extractPostTableFromRebuyAir, extractPreTableFromRebuyAir,
             extractPreTableFromFundsAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_eq, List.getElem?_replicate, h_lt, if_true,
             Option.map_some, Option.getD_some]

private lemma rebuy_post_get_seat_other
    (row : CommonRow) (ext : RebuyMethodColumns) (max_players : Nat) (seat_index : Nat)
    (i : Nat) (h_ne : i ≠ seat_index) (h_lt : i < max_players) :
    (extractPostTableFromRebuyAir row ext max_players seat_index).get_seat i =
      (extractPreTableFromRebuyAir row ext max_players seat_index).get_seat i := by
  have h_ne' : seat_index ≠ i := Ne.symm h_ne
  simp only [extractPostTableFromRebuyAir, extractPreTableFromRebuyAir,
             extractPreTableFromFundsAir, TexasPokerTable.get_seat,
             TexasPokerTable.update_seat, List.getD_eq_getD_get?, List.get?_eq_getElem?,
             List.getElem?_modify_ne _ _ h_ne', List.getElem?_replicate, h_lt, if_true,
             Option.getD_some]

private lemma rebuy_params_seat
    (ext : RebuyMethodColumns) :
    (extractRebuyParamsFromAir ext).seat_index = ext.input_seat_index.val := by
  simp [extractRebuyParamsFromAir]

private lemma rebuy_params_amount
    (ext : RebuyMethodColumns) :
    (extractRebuyParamsFromAir ext).amount =
      decodeU64 ext.input_amount.1 ext.input_amount.2.1
        ext.input_amount.2.2.1 ext.input_amount.2.2.2 := by
  simp [extractRebuyParamsFromAir]

/-! ### rebuy AIR soundness 主定理 -/

theorem rebuy_air_sound :
  ∀ (row : CommonRow) (ext : RebuyMethodColumns)
    (expected_seat_index : Nat) (expected_amount : Nat) (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    (hseat : expected_seat_index < max_players),
    RebuyAirAcceptable row ext expected_seat_index expected_amount max_players hlt →
    -- Limb range constraints（由 Rust AIR 的独立 range constraint 保证）
    Limb4Range16 ext.pre_stack →
    Limb4Range16 ext.input_amount →
    ContractRebuy
      (extractPreTableFromRebuyAir row ext max_players expected_seat_index)
      (extractRebuyParamsFromAir ext)
      (extractPostTableFromRebuyAir row ext max_players expected_seat_index) := by
  intro row ext expected_seat_index expected_amount max_players hlt hseat h_air
    h_range_pre h_range_amt
  -- 1. 解构 AIR 假设
  have h_active : row.is_active = M31.one := h_air.2.2.2
  have h_method : RebuyMethodConstraints row ext expected_seat_index expected_amount
      max_players hlt := h_air.2.1
  -- 2. 应用 active 前提得到约束合取
  have h_c := h_method h_active
  rcases h_c with ⟨h_ver, h_rs_unch, h_seat_eq, _h_amt_eq, h_amt_pos,
                    _h_occ, h_st0, h_st1, h_st2, h_st3, h_addon_pool, _h_src⟩
  -- 3. 关键派生：seat_index 一致性
  have h_seat_val : ext.input_seat_index.val = expected_seat_index := by
    rw [h_seat_eq]; simp [nat_to_m31]
  have h_params_seat : (extractRebuyParamsFromAir ext).seat_index = expected_seat_index := by
    rw [rebuy_params_seat, h_seat_val]
  have h_params_amount : (extractRebuyParamsFromAir ext).amount =
      decodeU64 ext.input_amount.1 ext.input_amount.2.1
        ext.input_amount.2.2.1 ext.input_amount.2.2.2 := rebuy_params_amount ext
  -- 4. 约束前提展开（active 成立）
  have h_ver' : decodeU64 row.post_version.1 row.post_version.2.1
                  row.post_version.2.2.1 row.post_version.2.2.2 =
                decodeU64 row.pre_version.1 row.pre_version.2.1
                  row.pre_version.2.2.1 row.pre_version.2.2.2 + 1 := h_ver h_active
  have h_rs' : row.post_round_state = row.pre_round_state := h_rs_unch h_active
  -- 5. stack 守恒（逐 limb → decodeU64 线性）
  have h_stack_eq :
      decodeU64 ext.post_stack.1 ext.post_stack.2.1
        ext.post_stack.2.2.1 ext.post_stack.2.2.2 =
      decodeU64 ext.pre_stack.1 ext.pre_stack.2.1
        ext.pre_stack.2.2.1 ext.pre_stack.2.2.2 +
      decodeU64 ext.input_amount.1 ext.input_amount.2.1
        ext.input_amount.2.2.1 ext.input_amount.2.2.2 := by
    rw [h_st0, h_st1, h_st2, h_st3]
    exact decodeU64_limb_add ext.pre_stack ext.input_amount
      h_range_pre h_range_amt
  -- 6. addon_pool 守恒
  have h_addon_pool' :
      decodeU64 ext.output_post_addon_pool.1 ext.output_post_addon_pool.2.1
        ext.output_post_addon_pool.2.2.1 ext.output_post_addon_pool.2.2.2 =
      decodeU64 ext.input_pre_addon_pool.1 ext.input_pre_addon_pool.2.1
        ext.input_pre_addon_pool.2.2.1 ext.input_pre_addon_pool.2.2.2 +
      decodeU64 ext.input_amount.1 ext.input_amount.2.1
        ext.input_amount.2.2.1 ext.input_amount.2.2.2 := h_addon_pool
  -- 7. 座位级引理
  have h_pre_seat : (extractPreTableFromRebuyAir row ext max_players expected_seat_index).get_seat
      expected_seat_index =
      { Seat.empty with
        player := PlayerId.ofNat 1,
        stack := decodeU64 ext.pre_stack.1 ext.pre_stack.2.1
            ext.pre_stack.2.2.1 ext.pre_stack.2.2.2 } :=
    rebuy_pre_get_seat_at_index row ext max_players expected_seat_index hseat
  have h_post_seat : (extractPostTableFromRebuyAir row ext max_players expected_seat_index).get_seat
      expected_seat_index =
      { Seat.empty with
        player := PlayerId.ofNat 1,
        stack := decodeU64 ext.post_stack.1 ext.post_stack.2.1
            ext.post_stack.2.2.1 ext.post_stack.2.2.2 } :=
    rebuy_post_get_seat_at_index row ext max_players expected_seat_index hseat
  -- 8. 证明 ContractRebuy 的 12 个合取
  unfold ContractRebuy
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · -- 1. params.seat_index < pre.max_players
    rw [h_params_seat, rebuy_pre_max_players]; exact hseat
  · -- 2. params.amount > 0
    rw [h_params_amount]; exact h_amt_pos
  · -- 3. (pre.get_seat params.seat_index).is_occupied = true
    rw [h_params_seat, h_pre_seat]
    simp [Seat.is_occupied, Seat.empty, EMPTY_PLAYER, PlayerId.ofNat]
  · -- 4. (post.get_seat ...).stack = (pre.get_seat ...).stack + params.amount
    rw [h_params_seat, h_post_seat, h_pre_seat, h_params_amount]
    exact h_stack_eq
  · -- 5. post.addon_pool = pre.addon_pool + params.amount
    rw [rebuy_post_addon_pool, rebuy_pre_addon_pool, h_params_amount]
    exact h_addon_pool'
  · -- 6. post.version = pre.version + 1
    rw [rebuy_post_version, rebuy_pre_version]; exact h_ver'
  · -- 7. ∀ i, i ≠ params.seat_index → i < pre.max_players → post.get_seat i = pre.get_seat i
    intro i h_ne h_lt
    rw [h_params_seat] at h_ne
    rw [rebuy_pre_max_players] at h_lt
    exact rebuy_post_get_seat_other row ext max_players expected_seat_index i h_ne h_lt
  · -- 8. post.round_state = pre.round_state
    rw [rebuy_post_round_state, rebuy_pre_round_state, h_rs']
  · -- 9. post.max_players = pre.max_players
    exact rebuy_post_max_players row ext max_players expected_seat_index
  · -- 10. post.big_blind = pre.big_blind
    rw [rebuy_post_big_blind, rebuy_pre_big_blind]
  · -- 11. post.small_blind = pre.small_blind
    rw [rebuy_post_small_blind, rebuy_pre_small_blind]
  · -- 12. post.hand_id = pre.hand_id
    rw [rebuy_post_hand_id, rebuy_pre_hand_id]

end PokerLean
