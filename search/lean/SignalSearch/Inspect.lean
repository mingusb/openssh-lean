import SignalSearch.Operation

open Lean CerbCertifiedInventory

namespace SignalSearch.Inspect

/-- Every executable expression root in the four expression-bearing snapshot
sections. A declaration contributes no root and must not be mistaken for an
empty, successfully analyzed body. -/
def siteRoot : SiteRow → Option Node
  | .function _ row => Operation.functionRoot row
  | .global (_, .GlobalDef _ body) => some (.effect body)
  | .global (_, .GlobalDecl _) => none
  | .implementation (_, .Def _ body) => some (.pure body)
  | .implementation (_, .IFun _ _ body) => some (.pure body)

private def details : Node → String × Option CerbLocation.Loc × List (String × Json)
  | .action (.Action location () body) =>
    let kind := match body with
      | .Load0 .. => "load"
      | .Store0 .. => "store"
      | .Alloc0 .. => "allocate"
      | .Create .. | .CreateReadOnly .. => "create"
      | .Kill .. => "kill"
      | _ => "action"
    (kind, some location, [])
  | .effect (.Expr annotations body) =>
    let (kind, extra) := match body with
      | .Eproc _ callee _ => ("call", [("callee", toJson callee)])
      | .Eccall .. => ("indirect-call", [])
      | .Eif .. | .Ecase .. => ("branch", [])
      | .Ememop operation _ => ("memory-operation", [("operation", toJson operation)])
      | _ => ("effect", [])
    (kind, get_loc annotations, extra)
  | .pure (.Pexpr annotations () body) =>
    let (kind, extra) := match body with
      | .PEcall callee _ => ("pure-call", [("callee", toJson callee)])
      | .PEmemop operation _ => ("pure-memory-operation", [("operation", toJson operation)])
      | .PEop operation _ _ => ("operator", [("operation", toJson operation)])
      | .PEif .. | .PEcase .. => ("pure-branch", [])
      | _ => ("pure", [])
    (kind, get_loc annotations, extra)

structure Visit where
  node : Node
  reversedAddress : List Nat
  location : Option CerbLocation.Loc
  locationOrigin : String

private def ownLocation : Node → Option CerbLocation.Loc
  | .action (.Action location () _) => some location
  | .effect (.Expr annotations _) => get_loc annotations
  | .pure (.Pexpr annotations () _) => get_loc annotations

/-- Total, structurally decreasing traversal with an address and source
location provenance for every typed expression occurrence. The same `children`
relation underlies the independently proved `extract_exact` theorem. -/
def visits (node : Node) (reversedAddress : List Nat := [])
    (inherited : Option CerbLocation.Loc := none) : List Visit :=
  let own := ownLocation node
  let location := own.or inherited
  let origin := if own.isSome then "own" else if inherited.isSome then "inherited" else "none"
  ⟨node, reversedAddress, location, origin⟩ ::
    ((children node).attach.zipIdx.flatMap fun pair =>
      visits pair.1.val (pair.2 :: reversedAddress) location)
termination_by measure node
decreasing_by
  exact immediate_measure_lt _ _ ((immediate_iff_mem _ _).mpr pair.1.property)

/-- Every emitted item comes from `visits`, whose node projection is proved
equal to the producer's complete extractor in `Coverage.visits_nodes`. -/
def sites (row : SiteRow) (kinds : Array String) : IO Json := do
  let some root := siteRoot row
    | throw <| IO.userError "The declaration has no body"
  let all := visits root
  let mut found : Array Json := #[]
  for visit in all do
    let (kind, _, extra) := details visit.node
    if kinds.isEmpty || kinds.contains kind then
      found := found.push <| Json.mkObj ([
        ("address", toJson visit.reversedAddress.reverse), ("kind", toJson kind),
        ("location", toJson visit.location),
        ("location_origin", toJson visit.locationOrigin)] ++ extra)
  return Json.mkObj [("status", toJson "sites"), ("section", toJson row.sourceSection),
    ("visited", toJson all.length),
    ("complete_node_count", toJson all.length),
    ("coverage_checked", toJson true),
    ("sites", toJson found), ("scope", toJson "typed syntactic operations, not execution reachability")]

end SignalSearch.Inspect
