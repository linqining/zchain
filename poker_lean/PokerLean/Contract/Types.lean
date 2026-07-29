import Mathlib
import PokerLean.Common.PoseidonHash

namespace PokerLean

structure PlayerId where
  val : Nat
deriving Repr, DecidableEq

namespace PlayerId
def ofNat (n : Nat) : PlayerId := ⟨n⟩
end PlayerId

def EMPTY_PLAYER : PlayerId := PlayerId.ofNat 0

inductive SeatStatus where
  | Empty | Waiting | Active | Folded | AllIn | Out
deriving Repr, DecidableEq

structure Seat where
  player : PlayerId
  stack : Nat
  bet : Nat
  total_bet : Nat
  folded : Bool
  all_in : Bool
  acted_this_round : Bool
  is_waiting : Bool
  left_during_hand : Bool
  pending_addon : Nat
  time_bank_ms : Nat
deriving Repr

namespace Seat

def empty : Seat := {
  player := EMPTY_PLAYER,
  stack := 0, bet := 0, total_bet := 0,
  folded := false, all_in := false, acted_this_round := false,
  is_waiting := false, left_during_hand := false,
  pending_addon := 0, time_bank_ms := 0
}

def status (s : Seat) : SeatStatus :=
  if s.player = EMPTY_PLAYER then SeatStatus.Empty
  else if s.left_during_hand then SeatStatus.Out
  else if s.is_waiting then SeatStatus.Waiting
  else if s.folded then SeatStatus.Folded
  else if s.all_in then SeatStatus.AllIn
  else SeatStatus.Active

def is_participating (s : Seat) : Bool :=
  s.player ≠ EMPTY_PLAYER && not s.left_during_hand && not s.is_waiting && not s.folded

/-- 座位是否被占用（玩家非空）。对齐合约 `Seat::is_occupied`。 -/
def is_occupied (s : Seat) : Bool := s.player ≠ EMPTY_PLAYER

/-- 座位是否为空。 -/
def is_empty (s : Seat) : Bool := s.player = EMPTY_PLAYER

theorem empty_seat_not_occupied :
    Seat.empty.is_occupied = false := by
  simp [Seat.empty, is_occupied, EMPTY_PLAYER, PlayerId.ofNat]

def mark_folded (s : Seat) : Seat :=
  { s with folded := true, acted_this_round := true }

/-- 被踢出玩家的座位状态（对齐 Rust `kick_player_internal`）：
    保留 player 不变，但 folded/left_during_hand = true，
    stack/bet 清零，all_in/acted_this_round/is_waiting 复位。 -/
def kicked (s : Seat) : Seat :=
  { s with
    stack := 0, bet := 0,
    folded := true, left_during_hand := true,
    all_in := false, acted_this_round := false, is_waiting := false }

end Seat

inductive RoundState where
  | ROUND_WAITING | ROUND_PREFLOP | ROUND_FLOP | ROUND_TURN | ROUND_RIVER | ROUND_SHOWDOWN
deriving Repr, DecidableEq

namespace RoundState

/-- 与 Rust `constants.rs` 逐字节对齐：
    WAITING=0, PREFLOP=2, FLOP=3, TURN=4, RIVER=5, SHOWDOWN=6（值 1 未使用） -/
def toNat : RoundState → Nat
  | ROUND_WAITING => 0 | ROUND_PREFLOP => 2 | ROUND_FLOP => 3
  | ROUND_TURN => 4 | ROUND_RIVER => 5 | ROUND_SHOWDOWN => 6

def fromNat (n : Nat) : RoundState :=
  if n = 2 then ROUND_PREFLOP
  else if n = 3 then ROUND_FLOP
  else if n = 4 then ROUND_TURN
  else if n = 5 then ROUND_RIVER
  else if n = 6 then ROUND_SHOWDOWN
  else ROUND_WAITING

theorem fromNat_zero : fromNat 0 = ROUND_WAITING := rfl

theorem round_state_ofNat_zero : fromNat 0 = ROUND_WAITING := rfl

theorem fromNat_two : fromNat 2 = ROUND_PREFLOP := rfl

def is_betting_round : RoundState → Bool
  | ROUND_PREFLOP => true | ROUND_FLOP => true
  | ROUND_TURN => true | ROUND_RIVER => true | _ => false

theorem round_state_waiting_is_not_betting :
  ¬ROUND_WAITING.is_betting_round := by simp [is_betting_round]

theorem round_state_preflop_is_betting :
  ROUND_PREFLOP.is_betting_round := by simp [is_betting_round]

end RoundState

structure BettingRoundState where
  current_bet : Nat
  current_turn : Nat
  dealer_seat : Nat
  pot : Nat
  side_pots : List Nat
  min_raise : Nat
  last_aggressor : Nat
  num_raises : Nat
deriving Repr

structure ShuffleState where
  phase : Nat
  current_shuffler : Option Nat
  pending_players : List Nat
  completed_players : List Nat
deriving Repr

structure RevealTokenState where
  reveal_phase : Nat
  num_assignments : Nat
deriving Repr

inductive DeckState where
  | DeckIdle | DeckShuffling | DeckRevealed
deriving Repr, DecidableEq

inductive ReconstructState where
  | ReconstructIdle | Reconstructing | Reconstructed
deriving Repr, DecidableEq

namespace ReconstructState

def toNat : ReconstructState → Nat
  | ReconstructIdle => 0 | Reconstructing => 1 | Reconstructed => 2

def fromNat (n : Nat) : ReconstructState :=
  if n = 1 then Reconstructing
  else if n = 2 then Reconstructed
  else ReconstructIdle

end ReconstructState

structure TexasPokerTable where
  table_id : Nat
  name_hash : Nat
  seats : List Seat
  max_players : Nat
  small_blind : Nat
  big_blind : Nat
  ante : Nat
  version : Nat
  round_state : RoundState
  betting : BettingRoundState
  shuffle_state : ShuffleState
  reveal_state : RevealTokenState
  deck_state : DeckState
  reconstruct_state : ReconstructState
  hand_id : Nat
  call_seq : Nat
  chip_pool : Nat
  addon_pool : Nat
  pending_addon_total : Nat
  pending_rebuy_total : Nat
  rake : Nat
  table_fee : Nat
  is_private : Bool
  started_at : Nat
  timeout : Nat
  last_action_time : Nat
deriving Repr

namespace TexasPokerTable

def get_seat (t : TexasPokerTable) (idx : Nat) : Seat :=
  List.getD t.seats idx Seat.empty

def update_seat (t : TexasPokerTable) (idx : Nat) (f : Seat → Seat) : TexasPokerTable :=
  { t with seats := List.modify f idx t.seats }

def all_seats_empty (t : TexasPokerTable) : Bool :=
  t.seats.all (fun s : Seat => s.player = EMPTY_PLAYER)

def init (table_id name_hash max_players small_blind big_blind : Nat)
    (is_private : Bool) (timeout : Nat)
    (_hmax : 2 ≤ max_players ∧ max_players ≤ 9)
    (_hbb : big_blind > 0)
    (_hsb : small_blind ≤ big_blind) : TexasPokerTable := by
  let bs : BettingRoundState := {
    current_bet := 0, current_turn := 0, dealer_seat := 0,
    pot := 0, side_pots := [], min_raise := big_blind,
    last_aggressor := 0, num_raises := 0
  }
  let ss : ShuffleState := {
    phase := 0, current_shuffler := none,
    pending_players := [], completed_players := []
  }
  let rs : RevealTokenState := { reveal_phase := 0, num_assignments := 0 }
  exact {
    table_id := table_id,
    name_hash := name_hash,
    seats := List.replicate max_players Seat.empty,
    max_players := max_players,
    small_blind := small_blind,
    big_blind := big_blind,
    ante := 0, version := 1,
    round_state := RoundState.ROUND_WAITING,
    betting := bs,
    shuffle_state := ss,
    reveal_state := rs,
    deck_state := DeckState.DeckIdle,
    reconstruct_state := ReconstructState.ReconstructIdle,
    hand_id := 0, call_seq := 0,
    chip_pool := 0, addon_pool := 0,
    pending_addon_total := 0, pending_rebuy_total := 0,
    rake := 0, table_fee := 0,
    is_private := is_private, started_at := 0, timeout := timeout, last_action_time := 0
  }

def empty_table : TexasPokerTable := by
  let bs : BettingRoundState := {
    current_bet := 0, current_turn := 0, dealer_seat := 0,
    pot := 0, side_pots := [], min_raise := 0,
    last_aggressor := 0, num_raises := 0
  }
  let ss : ShuffleState := {
    phase := 0, current_shuffler := none,
    pending_players := [], completed_players := []
  }
  let rs : RevealTokenState := { reveal_phase := 0, num_assignments := 0 }
  exact {
    table_id := 0, name_hash := 0, seats := [], max_players := 0,
    small_blind := 0, big_blind := 0, ante := 0, version := 0,
    round_state := RoundState.ROUND_WAITING,
    betting := bs,
    shuffle_state := ss,
    reveal_state := rs,
    deck_state := DeckState.DeckIdle,
    reconstruct_state := ReconstructState.ReconstructIdle,
    hand_id := 0, call_seq := 0,
    chip_pool := 0, addon_pool := 0,
    pending_addon_total := 0, pending_rebuy_total := 0,
    rake := 0, table_fee := 0,
    is_private := false, started_at := 0, timeout := 0, last_action_time := 0
  }

end TexasPokerTable

/-! ## State Preimage Bridge

将 `TexasPokerTable` 映射到 `StatePreimage`，用于 Poseidon252 哈希。
该映射抽象化了 Rust 端 `table_state_preimage` 的实现细节。
-/

/-- 从 TexasPokerTable 生成 StatePreimage（抽象编码）。 -/
axiom texasPokerTableToPreimage (t : TexasPokerTable) : StatePreimage

end PokerLean
