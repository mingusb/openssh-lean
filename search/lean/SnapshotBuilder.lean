import SignalSearch.SnapshotImport
import Lean.Meta.Check

open Lean

namespace SignalSearch

private def builderString (request : Json) (key : String) : IO String :=
  IO.ofExcept <| request.getObjValAs? String key

private def builderField (json : Json) (name : String) (value : Json) : Json :=
  match json.getObj? with
  | .ok object => Json.mkObj ((name, value) :: object.toList)
  | .error _ => json

/-- Import and serialize one checked Core snapshot with no search-proof imports.
The resulting module depends on SnapshotImport and its transitive semantic
imports; adding a search theorem cannot change this builder environment. -/
unsafe def snapshotBuilderMain (args : List String) : IO UInt32 := do
  unless args.isEmpty do
    throw <| IO.userError "Snapshot builder takes no module arguments"
  initSearchPath (← findSysroot)
  enableInitializersExecution
  let mut env ← importModules #[{ module := `SignalSearch.SnapshotImport }] {} 0
    (loadExts := true)
  let input ← IO.getStdin
  let output ← IO.getStdout
  let mut loaded : Option Name := none
  repeat
    let line ← input.getLine
    if line.isEmpty then break
    let started ← IO.monoNanosNow
    let response ← try
      let request ← IO.ofExcept <| Json.parse line
      let op ← builderString request "op"
      if op == "ping" then
        pure <| Json.mkObj [("status", toJson "ready")]
      else if op == "verify_snapshot_binding" then
        verifySnapshotBinding (← builderString request "binding_path")
          (← builderString request "binding_sha256")
          (← builderString request "translator_path")
          (← builderString request "translator_sha256")
        pure <| Json.mkObj [("status", toJson "binding-verified")]
      else if op == "load_snapshot" then
        unless loaded.isNone do
          throw <| IO.userError "Snapshot builder already loaded a model"
        let name := (← builderString request "name").toName
        let digest ← builderString request "sha256"
        let (updated, timing) ← importSnapshot env
          (← builderString request "path") digest name
        env := updated
        loaded := some name
        pure <| Json.mkObj [("status", toJson "snapshot-loaded"),
          ("name", toJson name.toString), ("artifact_sha256", toJson digest),
          ("timing", timing)]
      else if op == "write_snapshot_module" then
        let moduleName ← builderString request "module"
        let path ← builderString request "path"
        let name := (← builderString request "name").toName
        CerbCoreQuote.requireAbsolute path
        unless path.endsWith ".olean" &&
            moduleName.startsWith "PinnedCoreCache.k_" &&
            loaded == some name && !env.isImportedConst name do
          throw <| IO.userError "Snapshot builder requires one locally checked model"
        writeModule (env.setMainModule moduleName.toName) path (writeIR := false)
        pure <| Json.mkObj [("status", toJson "snapshot-module-written"),
          ("module", toJson moduleName), ("name", toJson name.toString)]
      else throw <| IO.userError s!"Unknown snapshot-builder operation: {op}"
    catch e => pure <| Json.mkObj [("status", toJson "error"),
      ("error", toJson e.toString)]
    let elapsed := (← IO.monoNanosNow) - started
    output.putStrLn <| (builderField response "elapsed_ns" (toJson elapsed)).compress
    output.flush
  return 0

end SignalSearch

unsafe def main (args : List String) : IO UInt32 :=
  SignalSearch.snapshotBuilderMain args
