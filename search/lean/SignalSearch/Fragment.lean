import CerbCoreData
import CerbCertifiedInventory
import Lean

open Lean

namespace SignalSearch

abbrev FunctionRow := sym × generic_fun_map_decl Unit Unit
abbrev GlobalRow := sym × generic_globs Unit Unit
abbrev ImplementationRow := implementation_constant × generic_impl_decl Unit

/-- The expression-bearing sections of an archived Core snapshot. Other
sections are still required for execution, but have no expression root for
the typed site traversal. -/
inductive SiteRow where
  | function (origin : String) (row : FunctionRow)
  | global (row : GlobalRow)
  | implementation (row : ImplementationRow)

def SiteRow.sourceSection : SiteRow → String
  | .function origin _ => origin
  | .global _ => "globs"
  | .implementation _ => "impl0"

private def quoteJSON (α : Type) [FromJson α] [ToExpr α] (json : Json) :
    Except String Expr := do
  let value : α ← fromJson? json
  return toExpr value

/-- All twelve snapshot sections use the producer's actual datatypes and codecs.
This validates a fragment's type, not its behavioral reachability. -/
def decodeFragment (field : String) (json : Json) : Except String Expr :=
  match field with
  | "funs" | "stdlib" => quoteJSON FunctionRow json
  | "globs" => quoteJSON (sym × generic_globs Unit Unit) json
  | "tagDefs" => quoteJSON (sym × (CerbLocation.Loc × tag_definition)) json
  | "enumDefs" => quoteJSON (sym × integerType) json
  | "impl0" => quoteJSON (implementation_constant × generic_impl_decl Unit) json
  | "extern" => quoteJSON (identifier × (List sym × linking_kind)) json
  | "funinfo" => quoteJSON
      (sym × (CerbLocation.Loc × attributes × ctype × List (Option sym × ctype) × Bool × Bool)) json
  | "loopAttributes" => quoteJSON (Nat × loop_attribute) json
  | "visibleObjects" => quoteJSON (Nat × List (sym × ctype)) json
  | "main" => quoteJSON (Option sym) json
  | "callingConvention" => quoteJSON calling_convention json
  | other => .error s!"Unknown Core section: {other}"

private def readCheckedJSON (path expectedSHA : String) : IO Json := do
  CerbCoreQuote.requireAbsolute path
  unless (← CerbCoreQuote.hashFile "sha256sum" path 64) == expectedSHA do
    throw <| IO.userError "Core fragment hash mismatch"
  let raw ← IO.FS.readFile path
  unless (← CerbCoreQuote.hashFile "sha256sum" path 64) == expectedSHA do
    throw <| IO.userError "Core fragment changed during reading"
  IO.ofExcept <| Json.parse raw

/-- Decode one expression-bearing Core row for syntax inspection without
quoting it as a Lean declaration or extending a proof environment. -/
def readSiteRow (field path expectedSHA : String) : IO SiteRow := do
  let json ← readCheckedJSON path expectedSHA
  if field == "funs" || field == "stdlib" then
    let row : FunctionRow ← IO.ofExcept <| fromJson? json
    return .function field row
  else if field == "globs" then
    let row : GlobalRow ← IO.ofExcept <| fromJson? json
    return .global row
  else if field == "impl0" then
    let row : ImplementationRow ← IO.ofExcept <| fromJson? json
    return .implementation row
  else
    throw <| IO.userError s!"Section has no executable expression scanner: {field}"

def readFragment (field path expectedSHA : String) : IO (Expr × Option SiteRow) := do
  let json ← readCheckedJSON path expectedSHA
  if field == "funs" || field == "stdlib" then
    let row : FunctionRow ← IO.ofExcept <| fromJson? json
    return (toExpr row, some (.function field row))
  else if field == "globs" then
    let row : GlobalRow ← IO.ofExcept <| fromJson? json
    return (toExpr row, some (.global row))
  else if field == "impl0" then
    let row : ImplementationRow ← IO.ofExcept <| fromJson? json
    return (toExpr row, some (.implementation row))
  else
    return (← IO.ofExcept <| decodeFragment field json, none)

end SignalSearch
