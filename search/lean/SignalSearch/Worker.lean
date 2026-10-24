import SignalSearch
import SignalSearch.Inspect
import SignalSearch.SnapshotImport
import Lean.Elab.Tactic
import Lean.Meta.Check
import Lean.Util.CollectAxioms
import Lean.Meta.DiscrTree

open Lean Meta Elab

namespace SignalSearch

/-- Live nodes share Lean's persistent contexts. Durable jobs record the root
query and the tactic edges; replay is needed only after restarting the worker. -/
structure SearchNode where
  base : Environment
  saved : Term.SavedState
  proposition : Expr
  proof : Expr
  goals : List MVarId
  steps : Array String

private def restoreNode (node : SearchNode) : TermElabM Unit := do
  -- Ordinary SavedState.restore is for backtracking in one running elaborator:
  -- it deliberately leaves fresh-name generators and caches untouched. These
  -- nodes cross separate CoreM invocations, so restore the full snapshot.
  modifyThe Core.State fun _ => node.saved.meta.core.toState
  modifyThe Meta.State fun _ => node.saved.meta.meta
  modifyThe Term.State fun _ => node.saved.elab

private def parse (category : Name) (text : String) : TermElabM Syntax := do
  match Parser.runParserCategory (← getEnv) category text with
  | .ok stx => return stx
  | .error message => throwError message

private def rejectErrors : TermElabM Unit := do
  if (← Core.getMessageLog).hasErrors then
    throwError "Elaboration produced errors"

def startNode (text : String) : TermElabM SearchNode := do
  let proposition ← Term.elabType (← parse `term text)
  Term.synthesizeSyntheticMVarsNoPostponing
  let proposition ← instantiateMVars proposition
  unless ← isProp proposition do throwError "The requested outcome must have type Prop"
  if proposition.hasMVar || proposition.hasFVar then
    throwError "The query has unresolved parameters"
  rejectErrors
  let proof ← mkFreshExprMVar proposition
  return { base := ← getEnv, saved := ← Term.saveState, proposition, proof,
           goals := [proof.mvarId!], steps := #[] }

def extendNode (node : SearchNode) (tactic : String) : TermElabM SearchNode := do
  restoreNode node
  let goal :: rest := node.goals | throwError "The query is already proved"
  let stx ← parse `tactic tactic
  let generated ← Tactic.run goal (Tactic.evalTactic stx)
  Term.synthesizeSyntheticMVarsNoPostponing
  rejectErrors
  let goals ← (generated ++ rest).filterM fun g => return !(← g.isAssigned)
  return { node with saved := ← Term.saveState, goals, steps := node.steps.push tactic }

/- Tactics may create auxiliary theorems. Persist their dependency DAG, not just
the final expression: the next process has none of the search's temporary env. -/
private partial def proofDependencies (base : Environment) (expressions : Array Expr)
    (seen : Std.HashSet Name := {}) (declarations : Array Json := #[])
    : TermElabM (Std.HashSet Name × Array Json) := do
  let mut seen := seen
  let mut declarations := declarations
  for expression in expressions do
    for name in expression.getUsedConstants do
      if seen.contains name then continue
      seen := seen.insert name
      if base.contains name then continue
      let info ← getConstInfo name
      let (kind, type, value, params) ← match info with
        | .thmInfo d => pure ("theorem", d.type, d.value, d.levelParams)
        | .defnInfo d =>
          if d.safety != .safe then throwError "Unsafe proof dependency: {name}"
          pure ("definition", d.type, d.value, d.levelParams)
        | _ => throwError "Unsupported proof-local declaration: {name}"
      let (updated, deps) ← proofDependencies base #[type, value] seen declarations
      seen := updated
      declarations := deps.push <| Json.mkObj [
        ("name", toJson name.toString), ("kind", toJson kind),
        ("level_params", toJson (params.map Name.toString)),
        ("type", CerbCoreQuote.exprToJson type), ("value", CerbCoreQuote.exprToJson value)]
  return (seen, declarations)

private def restoreDependencies (declarations : Array Json) : TermElabM Unit := do
  for declaration in declarations do
    let name := (← IO.ofExcept <| declaration.getObjValAs? String "name").toName
    if (← getEnv).contains name then throwError "Certificate cannot replace {name}"
    let kind ← IO.ofExcept <| declaration.getObjValAs? String "kind"
    let levelParams := (← IO.ofExcept <| declaration.getObjValAs? (List String) "level_params").map String.toName
    let type ← IO.ofExcept <| CerbCoreQuote.exprFromJson? (← IO.ofExcept <| declaration.getObjVal? "type")
    let value ← IO.ofExcept <| CerbCoreQuote.exprFromJson? (← IO.ofExcept <| declaration.getObjVal? "value")
    if kind == "theorem" then
      addDecl <| .thmDecl { name, levelParams, type, value }
    else if kind == "definition" then
      addDecl <| .defnDecl { name, levelParams, type, value, hints := .abbrev, safety := .safe }
    else throwError "Unsupported certificate declaration kind: {kind}"

private def checkedProof (base : Environment) (proposition proof : Expr) : TermElabM Json := do
  let proof ← instantiateMVars proof
  if proof.hasMVar || proof.hasFVar then throwError "The proof is not closed"
  unless ← isDefEq (← inferType proof) proposition do
    throwError "The proof does not establish the original query"
  checkWithKernel proof
  let name := `_signalSearchWitness
  addDecl <| .thmDecl { name, levelParams := [], type := proposition, value := proof }
  let axioms ← collectAxioms name
  if axioms.contains ``sorryAx then throwError "An admitted proof is not a search result"
  let (references, declarations) ← proofDependencies base #[proposition, proof]
  return Json.mkObj [("status", toJson "proved"), ("axioms", toJson (axioms.map Name.toString)),
    ("references", toJson (references.toArray.map Name.toString)),
    ("declarations", toJson declarations),
    ("proposition", CerbCoreQuote.exprToJson proposition),
    ("proof", CerbCoreQuote.exprToJson proof)]

def describeNode (node : SearchNode) : TermElabM Json := do
  restoreNode node
  let mut goals : Array Json := #[]
  for goal in node.goals do
    goals := goals.push <| toJson (← ppGoal goal).pretty
  let fields := [("goals", toJson goals), ("steps", toJson node.steps)]
  if !node.goals.isEmpty then
    return Json.mkObj (("status", toJson "open") :: fields)
  let result ← checkedProof node.base node.proposition node.proof
  return Json.mkObj (fields ++ (← IO.ofExcept result.getObj?).toList)

/-- Compile rule conclusions once. The discrimination tree treats metavariables
as wildcards and retrieves unification candidates without scanning every rule. -/
structure RuleIndex where
  tree : DiscrTree String := {}
  count : Nat := 0

def indexRules (rules : Array String) : TermElabM RuleIndex := do
  let mut tree : DiscrTree String := {}
  for rule in rules do
    let value ← mkConstWithFreshMVarLevels rule.toName
    let (_, _, result) ← forallMetaTelescopeReducing (← inferType value)
    tree ← withReducible <| tree.insert result rule
  return { tree, count := rules.size }

/-- Generate proof-search edges from the actual pending goal and supplied semantic
lemmas. Constructors include input/trace constructors, so synthesis is not capped
at a predetermined collection of values or path lengths. -/
def choices (node : SearchNode) (rules : RuleIndex) : TermElabM Json := do
  restoreNode node
  let goal :: _ := node.goals | throwError "The query is already proved"
  goal.withContext do
    let original ← goal.getType
    let target ← whnf original
    let mut result := #["assumption", "rfl", "solve | omega", "solve | simp_all", "solve | decide"]
    let candidates ← rules.tree.getUnify original
    for rule in candidates do
      result := result.push s!"apply {rule}"
    if target.isForall then result := result.push "intro"
    if let .const head _ := target.getAppFn then
      if let some (.inductInfo info) := (← getEnv).find? head then
        for ctor in info.ctors do
          result := result.push s!"apply {ctor}"
    for localDecl in (← getLCtx) do
      if !localDecl.isImplementationDetail && (← isProp localDecl.type) then
        let type ← whnf localDecl.type
        if [``And, ``Or, ``Exists, ``False].contains type.getAppFn.constName! then
          result := result.push s!"cases {localDecl.userName}"
    return Json.mkObj [("status", toJson "choices"), ("tactics", toJson result),
      ("matching_rules", toJson candidates.size), ("rule_count", toJson rules.count)]

private def runTerm {α : Type} (env : Environment) (quantum : Nat)
    (action : TermElabM α) : IO (α × Environment) := do
  -- This is a scheduling quantum, supplied per request, not a path/search bound.
  let options := maxRecDepth.set (maxHeartbeats.set {} quantum)
    (if quantum == 0 then 0 else max 1024 quantum)
  let (result, state) ← Core.CoreM.toIO (MetaM.run' <| Term.TermElabM.run' action)
    { fileName := "<signal-search>", fileMap := default, options }
    { env }
  return (result, state.env)

private def stringField (request : Json) (name : String) : IO String :=
  IO.ofExcept <| request.getObjValAs? String name

private def naturalField (request : Json) (name : String) (fallback : Nat) : Nat :=
  (request.getObjValAs? Nat name).toOption.getD fallback

private def putField (json : Json) (name : String) (value : Json) : Json :=
  match json.getObj? with
  | .ok object => Json.mkObj ((name, value) :: object.toList)
  | .error _ => json

private def loadFragment (env : Environment) (request : Json) : IO (Json × Environment × Option SiteRow) := do
  let field ← stringField request "section"
  let name := (← stringField request "name").toName
  if env.contains name then throw <| IO.userError "Fragment name is already defined"
  let (value, row) ← readFragment field (← stringField request "path") (← stringField request "sha256")
  let (reply, updated) ← runTerm env (naturalField request "quantum" 0) do
    let type ← inferType value
    checkWithKernel value
    addDecl <| .defnDecl {
      name := name
      levelParams := []
      type := type
      value := value
      hints := .abbrev
      safety := .safe }
    return Json.mkObj [("status", toJson "loaded"), ("name", toJson name.toString),
      ("type", toJson (← ppExpr type).pretty)]
  return (reply, updated, row)

/-- A long-lived worker reuses imported semantics, decoded fragments and proof
contexts. The protocol also accepts an arbitrary imported query module. -/
unsafe def workerMain (modules : List String) : IO UInt32 := do
  initSearchPath (← findSysroot)
  let imports : Array Import := #[{ module := `SignalSearch }] ++
    modules.toArray.map (fun name => { module := name.toName })
  enableInitializersExecution
  let mut env ← importModules imports {} 0 (loadExts := true)
  let input ← IO.getStdin
  let output ← IO.getStdout
  let mut nodes : Std.HashMap Nat SearchNode := {}
  let mut nextNode := 0
  let mut ruleSets : Std.HashMap Nat RuleIndex := {}
  let mut nextRules := 0
  let mut fragments : Std.HashMap String SiteRow := {}
  let mut snapshotDecls : Array Name := #[]
  let mut locallyAdded := 0
  repeat
    let line ← input.getLine
    if line.isEmpty then break
    let started ← IO.monoNanosNow
    let response ← try
      let request ← IO.ofExcept <| Json.parse line
      let op ← stringField request "op"
      let quantum := naturalField request "quantum" 200000
      if op == "load" then
        let (reply, updated, row) ← loadFragment env request
        env := updated
        locallyAdded := locallyAdded + 1
        if let some row := row then
          fragments := fragments.insert (← stringField request "name") row
        pure reply
      else if op == "load_snapshot" then
        let name ← stringField request "name"
        let digest ← stringField request "sha256"
        let (updated, timing) ← importSnapshot env (← stringField request "path") digest name.toName
        env := updated
        locallyAdded := locallyAdded + 1
        snapshotDecls := snapshotDecls.push name.toName
        pure <| Json.mkObj [("status", toJson "snapshot-loaded"),
          ("name", toJson name), ("artifact_sha256", toJson digest),
          ("timing", timing)]
      else if op == "verify_snapshot_binding" then
        verifySnapshotBinding (← stringField request "binding_path")
          (← stringField request "binding_sha256")
          (← stringField request "translator_path")
          (← stringField request "translator_sha256")
        pure <| Json.mkObj [("status", toJson "binding-verified")]
      else if op == "write_snapshot_module" then
        let moduleName ← stringField request "module"
        let path ← stringField request "path"
        let name ← stringField request "name"
        CerbCoreQuote.requireAbsolute path
        unless path.endsWith ".olean" &&
            moduleName.startsWith "PinnedCoreCache.k_" &&
            modules.isEmpty && locallyAdded == 1 && snapshotDecls == #[name.toName] &&
            fragments.isEmpty && nodes.isEmpty && ruleSets.isEmpty &&
            !env.isImportedConst name.toName do
          throw <| IO.userError "Snapshot module requires one locally checked model and no other worker declarations"
        writeModule (env.setMainModule moduleName.toName) path (writeIR := false)
        pure <| Json.mkObj [("status", toJson "snapshot-module-written"),
          ("module", toJson moduleName), ("name", toJson name)]
      else if op == "use_snapshot" then
        let name := (← stringField request "name").toName
        unless env.isImportedConst name do
          throw <| IO.userError "Snapshot declaration was not imported"
        let some (.defnInfo declaration) := env.find? name
          | throw <| IO.userError "Imported snapshot is not a checked definition"
        unless declaration.type == mkConst ``SavedCoreProofInput &&
            declaration.safety == .safe do
          throw <| IO.userError "Imported snapshot has the wrong type or safety"
        match declaration.hints with
        | .opaque => pure ()
        | _ => throw <| IO.userError "Imported snapshot has the wrong reducibility hint"
        pure <| Json.mkObj [("status", toJson "snapshot-in-use"),
          ("name", toJson name.toString)]
      else if op == "sites" then
        let name ← stringField request "name"
        let some row := fragments[name]? | throw <| IO.userError "Unknown loaded expression-bearing fragment"
        let kinds := (request.getObjValAs? (Array String) "kinds").toOption.getD #[]
        Inspect.sites row kinds
      else if op == "scan" then
        let field ← stringField request "section"
        let row ← readSiteRow field (← stringField request "path")
          (← stringField request "sha256")
        let kinds := (request.getObjValAs? (Array String) "kinds").toOption.getD #[]
        Inspect.sites row kinds
      else if op == "start" || op == "step" then
        let node ← if op == "start" then
          let query ← stringField request "goal"
          Prod.fst <$> runTerm env quantum (startNode query)
        else do
          let id := naturalField request "node" nextNode
          let some node := nodes[id]? | throw <| IO.userError "Unknown live proof node"
          let tactic ← stringField request "tactic"
          Prod.fst <$> runTerm env quantum (extendNode node tactic)
        let (reply, _) ← runTerm env quantum (describeNode node)
        let id := nextNode
        nextNode := nextNode + 1
        nodes := nodes.insert id node
        pure <| putField reply "node" (toJson id)
      else if op == "rules" then
        let names ← IO.ofExcept <| request.getObjValAs? (Array String) "names"
        let (index, _) ← runTerm env quantum (indexRules names)
        let id := nextRules
        nextRules := nextRules + 1
        ruleSets := ruleSets.insert id index
        pure <| Json.mkObj [("status", toJson "indexed"), ("rule_set", toJson id), ("count", toJson names.size)]
      else if op == "choices" then
        let id := naturalField request "node" nextNode
        let some node := nodes[id]? | throw <| IO.userError "Unknown live proof node"
        let rules ← match (request.getObjValAs? Nat "rule_set").toOption with
          | some id => match ruleSets[id]? with
            | some index => pure index
            | none => throw <| IO.userError "Unknown rule index"
          | none =>
            let names := (request.getObjValAs? (Array String) "rules").toOption.getD #[]
            Prod.fst <$> runTerm env quantum (indexRules names)
        let (reply, _) ← runTerm env quantum (choices node rules)
        pure reply
      else if op == "verify" then
        let goal ← stringField request "goal"
        let proof ← IO.ofExcept <| CerbCoreQuote.exprFromJson? (← IO.ofExcept <| request.getObjVal? "proof")
        let (reply, _) ← runTerm env quantum do
          let node ← startNode goal
          let declarations := (request.getObjValAs? (Array Json) "declarations").toOption.getD #[]
          restoreDependencies declarations
          checkedProof node.base node.proposition proof
        pure reply
      else if op == "drop" then
        nodes := nodes.erase (naturalField request "node" nextNode)
        pure <| Json.mkObj [("status", toJson "dropped")]
      else if op == "imports" then
        let mut paths : Array String := #[]
        for name in env.header.moduleNames do
          let path ← findOLean name
          paths := paths.push path.toString
          for suffix in ["olean.private", "olean.server", "ir"] do
            let extra := path.withExtension suffix
            if ← extra.pathExists then paths := paths.push extra.toString
        pure <| Json.mkObj [("status", toJson "imports"), ("paths", toJson paths)]
      else if op == "ping" then
        pure <| Json.mkObj [("status", toJson "ready"), ("live_nodes", toJson nodes.size)]
      else throw <| IO.userError s!"Unknown operation: {op}"
    catch e => pure <| Json.mkObj [("status", toJson "error"), ("error", toJson e.toString)]
    let elapsed := (← IO.monoNanosNow) - started
    output.putStrLn <| (putField response "elapsed_ns" (toJson elapsed)).compress
    output.flush
  return 0

end SignalSearch
