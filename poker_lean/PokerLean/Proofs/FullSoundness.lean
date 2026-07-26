import PokerLean.Common.M31
import PokerLean.Common.U64Encoding
import PokerLean.Common.CommonColumns
import PokerLean.Contract.Types
import PokerLean.Contract.CreateTable
import PokerLean.Contract.Fold
import PokerLean.AIR.AirBase
import PokerLean.AIR.CreateTableAir
import PokerLean.AIR.FoldAir
import PokerLean.Proofs.CreateTableSoundness

namespace PokerLean

def sr_valid_simple (t : TexasPokerTable)
    (root : M31 × M31 × M31 × M31) : Prop :=
  root.1.val = t.table_id % M31_P

def FullCreateTableConstraints
    (row : CommonRow)
    (ext : CreateTableRow)
    : Prop :=
  CreateTableMethodConstraints row ext ∧
  sr_valid_simple (extractPreTableFromAir row) row.pre_state_root ∧
  sr_valid_simple (extractPostTableFromAir row ext) row.post_state_root ∧
  (extractPreTableFromAir row).version = 0 ∧
  (extractPreTableFromAir row).round_state = RoundState.ROUND_WAITING ∧
  List.isEmpty (extractPreTableFromAir row).seats ∧
  (extractPostTableFromAir row ext).seats.length = ext.maxPlayers ∧
  (extractPostTableFromAir row ext).all_seats_empty ∧
  (extractPostTableFromAir row ext).max_players = ext.maxPlayers ∧
  (extractPostTableFromAir row ext).big_blind = ext.bigBlind ∧
  (extractPostTableFromAir row ext).small_blind = ext.smallBlind

def FullCreateTableAirAcceptable
    (row : CommonRow)
    (ext : CreateTableRow)
    : Prop :=
  CommonConstraints row MethodKind.CreateTable ∧
  FullCreateTableConstraints row ext ∧
  row.is_active = M31.one ∧
  row.is_padding = M31.zero

theorem full_create_table_soundness
    (row : CommonRow)
    (ext : CreateTableRow)
    (h_air : FullCreateTableAirAcceptable row ext) :
  ContractCreateTable
    (extractPreTableFromAir row)
    (extractParamsFromAir ext)
    (extractPostTableFromAir row ext) := by
  have hbase : CreateTableAirAcceptable row ext := by
    unfold CreateTableAirAcceptable
    rcases h_air with ⟨hc, hfull, hactive, hpadding⟩
    exact ⟨hc, hfull.1, hactive, hpadding⟩
  exact create_table_soundness row ext hbase

def decodeU64' (l0 l1 l2 l3 : M31) : Nat :=
  l0.val + l1.val * 65536 + l2.val * (65536 * 65536) + l3.val * (65536 * 65536 * 65536)

def FullFoldConstraints
    (row : CommonRow)
    (ext : FoldMethodColumns)
    (expected_seat_index : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    : Prop :=
  FoldMethodConstraints row ext expected_seat_index hlt ∧
  (row.pre_round_state.val = 1 ∨ row.pre_round_state.val = 2 ∨
   row.pre_round_state.val = 3 ∨ row.pre_round_state.val = 4) ∧
  expected_seat_index < max_players ∧
  decodeU64' row.post_version.1 row.post_version.2.1
      row.post_version.2.2.1 row.post_version.2.2.2 =
    decodeU64' row.pre_version.1 row.pre_version.2.1
      row.pre_version.2.2.1 row.pre_version.2.2.2 + 1 ∧
  decodeU64' row.post_pot.1 row.post_pot.2.1
      row.post_pot.2.2.1 row.post_pot.2.2.2 =
    decodeU64' row.pre_pot.1 row.pre_pot.2.1
      row.pre_pot.2.2.1 row.pre_pot.2.2.2 ∧
  row.post_round_state = row.pre_round_state ∧
  row.post_button = row.pre_button

def FullFoldAirAcceptable
    (row : CommonRow)
    (ext : FoldMethodColumns)
    (expected_seat_index : Nat)
    (max_players : Nat)
    (hlt : expected_seat_index < M31_P)
    : Prop :=
  CommonConstraints row MethodKind.Fold ∧
  FullFoldConstraints row ext expected_seat_index max_players hlt ∧
  row.is_active = M31.one ∧
  row.is_padding = M31.zero

end PokerLean
