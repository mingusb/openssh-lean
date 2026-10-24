import CerbCoreData
import Lean.Meta.Check

open Lean Elab Command

namespace SignalSearch

/-- A kernel-checked value for the exact saved CoreData artifact format. Its
metadata records the source binding, translator, and complete 12-section Core
snapshot. Import verification is an IO provenance check, not a translation
preservation theorem. -/
structure SavedCoreProofInput where
  artifactSHA256 : String
  sourceBindingPath : String
  sourceBindingSHA256 : String
  translatorPath : String
  translatorSHA256 : String
  schemaVersion : Nat
  semanticSwitches : String
  fieldNames : Array String
  supply : Nat
  addressSpaceTop : Int
  fuel : Nat
  executionDigest : String
  orderedDigests : List String
  linkedFunctionCount : Nat
  linkedGlobalCount : Nat
  core : CerbCoreQuote.CoreSnapshot

private def requiredString (object : Json) (field : String) : IO String :=
  IO.ofExcept <| object.getObjValAs? String field

private def parseJSON (raw : String) : IO Json :=
  IO.ofExcept <| Json.parse raw

/-- Recheck the linked C, frontend, runtime, and translator inputs without
decoding or quoting the large saved Core artifact. A cached module is usable
only after this provenance check succeeds again. -/
def verifySnapshotBinding (bindingPath expectedBindingSHA256
    translatorPath expectedTranslatorSHA256 : String) : IO Unit := do
  CerbCoreQuote.requireAbsolute bindingPath
  CerbCoreQuote.requireAbsolute translatorPath
  unless (← CerbCoreQuote.hashFile "sha256sum" bindingPath 64) == expectedBindingSHA256 do
    throw <| IO.userError "Saved Core source binding hash mismatch"
  let inputs ← CerbCoreQuote.verifyLinkedBinding bindingPath (some translatorPath)
  unless inputs.bindingSHA256 == expectedBindingSHA256 &&
      (← CerbCoreQuote.hashFile "sha256sum" translatorPath 64) == expectedTranslatorSHA256 do
    throw <| IO.userError "Saved Core source/translator binding changed"

/-- Import a byte-pinned, source-bound `CerbCoreData.Artifact` without calling
its operational `load`, which is tied to the translator executable and builds
a runtime file. The declaration contains the full typed snapshot. -/
def importSnapshot (env : Environment) (path expectedSHA256 : String)
    (declName : Name) : IO (Environment × Json) := do
  if env.contains declName then
    throw <| IO.userError "Snapshot name is already defined"
  let options := maxRecDepth.set (maxHeartbeats.set {} 0) 0
  let context : Command.Context := {
    fileName := "<signal-search-snapshot>"
    fileMap := default
    snap? := none
    cancelTk? := none
  }
  let action : Command.CommandElabM Json := do
    let started ← IO.monoNanosNow
    CerbCoreQuote.requireAbsolute path
    unless path.endsWith ".gz" do
      throwError "Saved Core snapshot path must identify a gzip stream"
    unless (← CerbCoreQuote.hashFile "sha256sum" path 64) == expectedSHA256 do
      throwError "Saved Core snapshot artifact hash mismatch"
    let unpacked ← IO.Process.output { cmd := "gzip", args := #["-dc", path] }
    unless unpacked.exitCode == 0 do
      throwError "Saved Core snapshot decompression failed: {unpacked.stderr}"
    let decompressed ← IO.monoNanosNow
    let json ← parseJSON unpacked.stdout
    let parsed ← IO.monoNanosNow
    let bindingPath ← requiredString json "sourceBindingPath"
    let bindingSHA256 ← requiredString json "sourceBindingSHA256"
    CerbCoreQuote.requireAbsolute bindingPath
    unless (← CerbCoreQuote.hashFile "sha256sum" bindingPath 64) == bindingSHA256 do
      throwError "Saved Core source binding hash mismatch"
    let binding ← parseJSON (← IO.FS.readFile bindingPath)
    let translator ← IO.ofExcept <| binding.getObjVal? "translator"
    let translatorPath ← requiredString translator "path"
    let translatorSHA256 ← requiredString translator "sha256"
    -- `verifyLinkedBinding` supplies the bound fuel, address-space limit and
    -- ordered C inputs used below to build the closed declaration.
    let inputs ← CerbCoreQuote.verifyLinkedBinding bindingPath (some translatorPath)
    unless inputs.bindingSHA256 == bindingSHA256 &&
        (← CerbCoreQuote.hashFile "sha256sum" translatorPath 64) == translatorSHA256 do
      throwError "Saved Core source/translator binding changed"
    let verified ← IO.monoNanosNow
    let artifact : CerbCoreData.Artifact ← IO.ofExcept <| fromJson? json
    let decoded ← IO.monoNanosNow
    unless artifact.schemaVersion == 1 &&
        artifact.sourceBindingPath == bindingPath &&
        artifact.sourceBindingSHA256 == inputs.bindingSHA256 &&
        artifact.translatorSHA256 == translatorSHA256 &&
        artifact.semanticSwitches == "gnu_pointer_conversions" &&
        artifact.fieldNames == CerbCoreQuote.linkedCoreFieldNames &&
        artifact.orderedDigests.length == inputs.cabs.length &&
        artifact.orderedDigests.length > 0 &&
        artifact.linkedFunctionCount == artifact.snapshot.funs.length &&
        artifact.linkedGlobalCount == artifact.snapshot.globs.length do
      throwError "Saved Core snapshot identity or field inventory differs"
    unless (← CerbCoreQuote.hashFile "sha256sum" path 64) == expectedSHA256 &&
        (← CerbCoreQuote.hashFile "sha256sum" bindingPath 64) == bindingSHA256 &&
        (← CerbCoreQuote.hashFile "sha256sum" translatorPath 64) == translatorSHA256 do
      throwError "Saved Core snapshot inputs changed during import"
    let snapshotExpr := toExpr artifact.snapshot
    let quoted ← IO.monoNanosNow
    if snapshotExpr.hasSorry || snapshotExpr.hasFVar || snapshotExpr.hasMVar ||
        snapshotExpr.hasLooseBVars then
      throwError "Saved Core snapshot contains an open or admitted term"
    let value := mkAppN (mkConst ``SavedCoreProofInput.mk) #[
      toExpr expectedSHA256, toExpr artifact.sourceBindingPath,
      toExpr artifact.sourceBindingSHA256, toExpr translatorPath,
      toExpr artifact.translatorSHA256, toExpr artifact.schemaVersion,
      toExpr artifact.semanticSwitches, toExpr artifact.fieldNames,
      toExpr artifact.supply, toExpr inputs.addressSpaceTop, toExpr inputs.fuel,
      toExpr artifact.executionDigest, toExpr artifact.orderedDigests,
      toExpr artifact.linkedFunctionCount, toExpr artifact.linkedGlobalCount,
      snapshotExpr]
    liftCoreM <| addDecl <| .defnDecl {
      name := declName
      levelParams := []
      type := mkConst ``SavedCoreProofInput
      value
      hints := .opaque
      safety := .safe
    }
    let checked ← IO.monoNanosNow
    return Json.mkObj [
      ("read_decompress_ns", toJson (decompressed - started)),
      ("json_parse_ns", toJson (parsed - decompressed)),
      ("identity_verify_ns", toJson (verified - parsed)),
      ("artifact_decode_ns", toJson (decoded - verified)),
      ("quote_ns", toJson (quoted - decoded)),
      ("kernel_add_decl_ns", toJson (checked - quoted)),
      ("total_ns", toJson (checked - started))]
  match ← EIO.toIO' <| (action context).run (Command.mkState env {} options) with
  | .error error =>
      throw <| IO.userError (← error.toMessageData.toString)
  | .ok (timing, state) =>
      unless state.env.contains declName do
        throw <| IO.userError "Snapshot importer did not declare the requested name"
      return (state.env, timing)

end SignalSearch
