import PokerLean.State.Betting
import PokerLean.State.SidePot
import PokerLean.State.HandEvaluator

/-!
# 差分对拍 runner（方案 C，`.trae/documents/rust-to-lean-proof-schemes.md`）

读取 Rust 侧生成器（`poker_l1/src/vm/contracts/texas_poker/tests/differential.rs`）
写出的 `cases.txt` / `expected.txt`，用 `PokerLean.State` 手工镜像模型逐行求值，
与真实 Rust 实现的输出比对。任一行不一致即报告并返回非零退出码。

本文件**不属于** `PokerLean` 库构建目标（不被 `PokerLean.lean` import），
仅作为可执行脚本运行：

```
cargo test -p poker_l1 --lib differential -- --nocapture
cd poker_lean && lake env lean --run Differential/Main.lean /tmp/zchain_diff
```

行格式见 Rust 生成器文档注释（B / SP / EB / EBP / W 五类用例）。
-/

open TexasPoker

/-- 解析 EB/EBP 用例剩余 token：`n idx0..idx{n-1}` → `evaluate_best` 结果行。 -/
def evalCards (rest : List String) : String :=
  let a := rest.map String.toNat!
  let n := a.getD 0 0
  let cards : List Card := (List.range n).map (fun i => Card.fromIndex (a.getD (1 + i) 0))
  let hr := HandRank.evaluate_best cards
  s!"{hr.category} {hr.k0} {hr.k1} {hr.k2} {hr.k3} {hr.k4}"

/-- 解析 W 用例剩余 token：`seat k idx×k` 重复 m 次 → (seat, 索引列表)。 -/
partial def parseHands : List String → List (Nat × List Nat) → Option (List (Nat × List Nat))
  | [], acc => some acc.reverse
  | seat :: k :: rest, acc =>
    let k := k.toNat!
    parseHands (rest.drop k) ((seat.toNat!, rest.take k |>.map String.toNat!) :: acc)
  | _, _ => none

/-- 对单条用例行用 Lean 模型求值，返回与 Rust expected 同构的输出行。 -/
def computeCase (line : String) : Option String :=
  let toks := (line.splitOn " ").filter (fun s => !s.isEmpty)
  match toks with
  | "B" :: rest =>
    let a := rest.map String.toNat!
    let cb := a.getD 0 0
    let mr := a.getD 1 0
    let sb := a.getD 2 0
    let st := a.getD 3 0
    let tb := a.getD 4 0
    let r : BettingRound := ⟨cb, mr⟩
    let ctc := r.chips_to_call sb
    let cc := (r.can_check sb).toNat
    let cl := (r.can_call sb st).toNat
    let cr := (r.can_raise sb st).toNat
    let aa := r.available_actions sb st
    let pc := r.process_call sb st
    let (rok, rcb, rmr, rn) := match r.process_raise tb sb st with
      | some (r', k) => (1, r'.current_bet, r'.min_raise, k)
      | none => (0, 0, 0, 0)
    some s!"{ctc} {cc} {cl} {cr} {aa} {pc} {rok} {rcb} {rmr} {rn}"
  | "SP" :: rest =>
    let a := rest.map String.toNat!
    let n := a.getD 0 0
    let seats : List SeatBet := (List.range n).map (fun i =>
      ⟨a.getD (1 + i) 0, (a.getD (1 + n + i) 0) == 1, (a.getD (1 + 2 * n + i) 0) == 1⟩)
    let pots := calculate_side_pots seats
    let body := String.intercalate " " (pots.map (fun p => s!"{p.amount} {p.eligible_seats}"))
    some s!"1 {pots.length} {body}"
  | "EB" :: rest => some (evalCards rest)
  | "EBP" :: rest => some (evalCards rest)
  | "W" :: _ :: rest => -- 跳过 m（手数）token，直接解析 (seat, k, idx×k) 序列
    match parseHands rest [] with
    | none => none
    | some parsed =>
      let hands : List (Nat × List Card) :=
        parsed.map (fun (s, cs) => (s, cs.map Card.fromIndex))
      let winners := HandRank.find_winners hands
      let body := String.intercalate " " (winners.map toString)
      some s!"{winners.length} {body}"
  | _ => none

def main : IO UInt32 := do
  -- 目录优先取 ZCHAIN_DIFF_DIR（与 Rust 生成器同一环境变量），默认 /tmp/zchain_diff
  let dir := match ← IO.getEnv "ZCHAIN_DIFF_DIR" with
    | some d => d
    | none => "/tmp/zchain_diff"
  let casesArr ← IO.FS.lines (System.FilePath.mk (dir ++ "/cases.txt"))
  let expectedArr ← IO.FS.lines (System.FilePath.mk (dir ++ "/expected.txt"))
  let caseLines := casesArr.filter (fun l => !l.isEmpty)
  let expLines := expectedArr.filter (fun l => !l.isEmpty)
  if caseLines.size != expLines.size then
    IO.println s!"FATAL: 行数不一致 cases={caseLines.size} expected={expLines.size}"
    return 2
  let n := caseLines.size
  let tags := #["B", "SP", "EB", "EBP", "W"]
  let mut totals : Array Nat := #[0, 0, 0, 0, 0]
  let mut fails : Array Nat := #[0, 0, 0, 0, 0]
  let mut reports : Array String := #[]
  for i in [0:n] do
    let c := caseLines[i]!
    let e := expLines[i]!
    let tag := ((c.splitOn " ").filter (fun s => !s.isEmpty)).headD "?"
    let tidx : Nat := match tag with
      | "B" => 0 | "SP" => 1 | "EB" => 2 | "EBP" => 3 | "W" => 4 | _ => 5
    let ok := tidx < 5
    if ok then
      totals := totals.set! tidx ((totals.get! tidx) + 1)
    match computeCase c with
    | none =>
      if ok then fails := fails.set! tidx ((fails.get! tidx) + 1)
      if reports.size < 20 then
        reports := reports.push s!"#{i} [{tag}] PARSE_ERROR\n  in:  {c}"
    | some actual =>
      if actual.trim != e.trim then
        if ok then fails := fails.set! tidx ((fails.get! tidx) + 1)
        if reports.size < 20 then
          reports := reports.push
            s!"#{i} [{tag}]\n  in:      {c}\n  rust:    {e}\n  lean:    {actual}"
  for r in reports do
    IO.println r
    IO.println ""
  IO.println "==== 差分对拍汇总 ===="
  for t in [0:5] do
    IO.println s!"  {tags[t]!}: total={totals.get! t} fail={fails.get! t}"
  let totalFail := (List.range 5).foldl (fun acc i => acc + fails.get! i) 0
  IO.println s!"  合计: total={n} fail={totalFail}"
  if totalFail == 0 then
    IO.println "PASS: Lean 模型与 Rust 实现在全部用例上一致"
    return 0
  else
    IO.println s!"FAIL: {totalFail} 例不一致（详见上方报告；仅显示前 20 例）"
    return 1
