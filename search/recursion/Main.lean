import SignalSearch.Coverage

/-!
Static, typed Core call-edge analysis over one hash-checked archived function
row. A reported edge is syntactic: it does not assert that its enclosing
branch is reachable, that recursion is unbounded, or that native execution
raises a signal.

This tool is intentionally outside the pinned SignalSearch worker source tree,
so the active all-target inventory retains its exact checked worker identity.
-/

open Lean CerbCertifiedInventory SignalSearch

namespace RecursionSearch

/-- A direct Core function-pointer value. This constructor form is emitted for
ordinary C calls after the frontend has resolved the callee symbol. Calls whose
callee is computed in another way remain unresolved, not silently discarded
from the complete typed-site inventory. -/
def specifiedSymbol : pexpr → Option sym
  | .Pexpr _ () (.PEctor Cspecified [.Pexpr _ () (.PEsym target)]) => some target
  | _ => none

def callTarget : Node → Option sym
  | .effect (.Expr _ (.Eccall _ _ callee _)) => specifiedSymbol callee
  | .effect (.Expr _ (.Eproc _ (.Sym target) _)) => some target
  | _ => none

def matchesOwner (row : FunctionRow) (target : Option sym) : Bool :=
  match target with
  | some symbol => toJson symbol == toJson row.1
  | none => false

def selfCalls (row : FunctionRow) : List SignalSearch.Inspect.Visit :=
  match SignalSearch.Operation.functionRoot row with
  | none => []
  | some root =>
      (SignalSearch.Inspect.visits root).filter fun visit =>
        matchesOwner row (callTarget visit.node)

/-- Every candidate is an actual occurrence in the archived function body,
and its resolved Core callee has the same serialized symbol key as the owner.
This is a syntactic statement; no execution path is asserted. -/
theorem selfCalls_sound (row : FunctionRow)
    (visit : SignalSearch.Inspect.Visit) (selected : visit ∈ selfCalls row) :
    matchesOwner row (callTarget visit.node) = true ∧
    ∃ root, SignalSearch.Operation.functionRoot row = some root ∧
      Occurs root visit.node := by
  unfold selfCalls at selected
  cases hroot : SignalSearch.Operation.functionRoot row with
  | none => simp [hroot] at selected
  | some root =>
      simp only [hroot] at selected
      obtain ⟨member, hMatch⟩ := List.mem_filter.mp selected
      have inNodes : visit.node ∈
          (SignalSearch.Inspect.visits root).map
            SignalSearch.Inspect.Visit.node := by
        exact List.mem_map.mpr ⟨visit, member, rfl⟩
      rw [SignalSearch.Coverage.visits_nodes root [] none] at inNodes
      exact ⟨hMatch, root, rfl, (extract_exact root visit.node).mp inNodes⟩

def candidateJSON (visit : SignalSearch.Inspect.Visit) : Json :=
  Json.mkObj [
    ("address", toJson visit.reversedAddress.reverse),
    ("location", toJson visit.location),
    ("location_origin", toJson visit.locationOrigin),
    ("kind", toJson "direct-self-call"),
    ("scope", toJson "typed Core syntax; dynamic reachability and native fault unproved")]

def scan (path expectedSHA : String) : IO Json := do
  let row ← SignalSearch.readSiteRow "funs" path expectedSHA
  match row with
  | .function _ functionRow =>
      let calls := selfCalls functionRow
      return Json.mkObj [
        ("status", toJson "scanned"),
        ("row_symbol", toJson functionRow.1),
        ("row_sha256", toJson expectedSHA),
        ("candidates", toJson (calls.map candidateJSON))]
  | _ => throw <| IO.userError "Expected a function row"

/-- One process can inspect any number of hash-pinned rows. The 14-program
driver below streams them through this protocol and reuses imported Lean
semantics; each row is decoded and traversed once. -/
def serve : IO UInt32 := do
  let input ← IO.getStdin
  let output ← IO.getStdout
  repeat
    let line ← input.getLine
    if line.isEmpty then break
    let reply ← try
      let request ← IO.ofExcept <| Json.parse line
      let path ← IO.ofExcept <| request.getObjValAs? String "path"
      let digest ← IO.ofExcept <| request.getObjValAs? String "sha256"
      scan path digest
    catch error =>
      pure <| Json.mkObj [("status", toJson "error"),
        ("message", toJson error.toString)]
    output.putStrLn reply.compress
    output.flush
  return 0

end RecursionSearch

unsafe def main (args : List String) : IO UInt32 := do
  match args with
  | ["--jsonl"] => RecursionSearch.serve
  | [path, expectedSHA] =>
      IO.println (← RecursionSearch.scan path expectedSHA).compress
      return 0
  | _ =>
      IO.eprintln "usage: recursion-search PATH SHA256 | --jsonl"
      return 2
