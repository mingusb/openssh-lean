import SignalSearch.CoreExecution
import SignalSearch.SiteFault

open CerbCertifiedInventory CerbMem CerberusImpl

namespace SignalSearch.SelectedRequestFault

private theorem foldl_prepend_keeps {α β : Type} (results : β → List α)
    (branches : List β) (acc : List α) (out : α) (found : out ∈ acc) :
    out ∈ branches.foldl (fun prior branch => results branch ++ prior) acc := by
  induction branches generalizing acc with
  | nil => simpa using found
  | cons branch rest ih =>
      simp only [List.foldl_cons]
      exact ih (results branch ++ acc) (List.mem_append.mpr (Or.inr found))

private theorem foldl_prepend_selects {α β : Type} (results : β → List α)
    (branches : List β) (acc : List α) (branch : β) (out : α)
    (selected : branch ∈ branches) (found : out ∈ results branch) :
    out ∈ branches.foldl (fun prior item => results item ++ prior) acc := by
  induction branches generalizing acc with
  | nil => cases selected
  | cons current rest ih =>
      simp only [List.foldl_cons]
      rcases List.mem_cons.mp selected with same | later
      · subst current
        exact foldl_prepend_keeps results rest (results branch ++ acc) out
          (List.mem_append.mpr (Or.inl found))
      · exact ih (results current ++ acc) later

/-- A structural path into the production nondeterminism tree. The remaining
fuel travels with the selected subtree; selecting a branch never resets the
runner's depth budget. Index 0 denotes a guard continuation or the left side
of a binary branch; index 1 denotes its right side. -/
inductive BranchPath {a info err cs st : Type} :
    Nat → ndM a info err cs st → st → List Nat →
      ndM a info err cs st → st → Nat → Prop where
  | here (fuel : Nat) (program : ndM a info err cs st) (state : st) :
      BranchPath fuel program state [] program state fuel
  | choice {fuel : Nat} {state next leafState : st}
      {index : Nat} {tail : List Nat} {remaining : Nat}
      {leaf selected : ndM a info err cs st}
      (step : st → nd_action a info err cs st × st)
      (label branchLabel : info)
      (branches : List (info × ndM a info err cs st))
      (evaluated : step state = (NDnd label branches, next))
      (picked : branches[index]? = some (branchLabel, selected))
      (further : BranchPath fuel selected next tail leaf leafState remaining) :
      BranchPath (fuel + 1) (ND step) state (index :: tail) leaf leafState remaining
  | stepChoice {fuel : Nat} {state next leafState : st}
      {index : Nat} {tail : List Nat} {remaining : Nat}
      {leaf selected : ndM a info err cs st}
      (step : st → nd_action a info err cs st × st)
      (label branchLabel : info)
      (branches : List (info × ndM a info err cs st))
      (evaluated : step state = (NDstep label branches, next))
      (picked : branches[index]? = some (branchLabel, selected))
      (further : BranchPath fuel selected next tail leaf leafState remaining) :
      BranchPath (fuel + 1) (ND step) state (index :: tail) leaf leafState remaining
  | guard {fuel : Nat} {state next leafState : st}
      {tail : List Nat} {remaining : Nat}
      {leaf continuation : ndM a info err cs st}
      (step : st → nd_action a info err cs st × st)
      (label : info) (constraint : cs)
      (evaluated : step state = (NDguard label constraint continuation, next))
      (further : BranchPath fuel continuation next tail leaf leafState remaining) :
      BranchPath (fuel + 1) (ND step) state (0 :: tail) leaf leafState remaining
  | left {fuel : Nat} {state next leafState : st}
      {tail : List Nat} {remaining : Nat}
      {leaf positive negative : ndM a info err cs st}
      (step : st → nd_action a info err cs st × st)
      (label : info) (constraint : cs)
      (evaluated : step state = (NDbranch label constraint positive negative, next))
      (further : BranchPath fuel positive next tail leaf leafState remaining) :
      BranchPath (fuel + 1) (ND step) state (0 :: tail) leaf leafState remaining
  | right {fuel : Nat} {state next leafState : st}
      {tail : List Nat} {remaining : Nat}
      {leaf positive negative : ndM a info err cs st}
      (step : st → nd_action a info err cs st × st)
      (label : info) (constraint : cs)
      (evaluated : step state = (NDbranch label constraint positive negative, next))
      (further : BranchPath fuel negative next tail leaf leafState remaining) :
      BranchPath (fuel + 1) (ND step) state (1 :: tail) leaf leafState remaining

/-- A selected subtree's result is a result of the unmodified exhaustive
runner. This applies to branch choices made inside the real driver and keeps
the same fuel exhaustion behavior. -/
theorem BranchPath.sound {a info err cs st : Type} {fuel remaining : Nat}
    {program leaf : ndM a info err cs st} {state leafState : st}
    {path : List Nat}
    (selected : BranchPath fuel program state path leaf leafState remaining)
    {outcome : nd_status a err st × List String × st}
    (result : outcome ∈ CerbND.runNDFuel remaining leaf leafState) :
    outcome ∈ CerbND.runNDFuel fuel program state := by
  induction selected with
  | here => exact result
  | choice step label branchLabel branches evaluated picked further ih =>
      have fromBranch := ih result
      simpa only [CerbND.runNDFuel, evaluated] using
        foldl_prepend_selects
          (fun branch : info × ndM a info err cs st =>
            CerbND.runNDFuel _ branch.2 _)
          branches [] (branchLabel, _) outcome (List.mem_of_getElem? picked) fromBranch
  | stepChoice step label branchLabel branches evaluated picked further ih =>
      have fromBranch := ih result
      simpa only [CerbND.runNDFuel, evaluated] using
        foldl_prepend_selects
          (fun branch : info × ndM a info err cs st =>
            CerbND.runNDFuel _ branch.2 _)
          branches [] (branchLabel, _) outcome (List.mem_of_getElem? picked) fromBranch
  | guard step label constraint evaluated further ih =>
      simpa only [CerbND.runNDFuel, evaluated] using ih result
  | left step label constraint evaluated further ih =>
      simpa only [CerbND.runNDFuel, evaluated, List.mem_append] using
        (Or.inl (ih result) :
          outcome ∈ CerbND.runNDFuel _ _ _ ∨ outcome ∈ CerbND.runNDFuel _ _ _)
  | right step label constraint evaluated further ih =>
      simpa only [CerbND.runNDFuel, evaluated, List.mem_append] using
        (Or.inr (ih result) :
          outcome ∈ CerbND.runNDFuel _ _ _ ∨ outcome ∈ CerbND.runNDFuel _ _ _)

/-- A concrete one-choice scheduler fixture: the selected branch's outcome
belongs to the original ND tree, with one unit of runner fuel consumed. -/
theorem BranchPath.singleChoice {a info err cs st : Type}
    (fuel : Nat) (state : st) (label : info)
    (selected : ndM a info err cs st) :
    BranchPath (fuel + 1)
      (ND (fun initial => (NDnd label [(label, selected)], initial)))
      state [0] selected state fuel := by
  exact .choice (fun initial => (NDnd label [(label, selected)], initial))
    label label [(label, selected)] rfl rfl (.here fuel selected state)

theorem BranchPath.singleChoice_sound {a info err cs st : Type}
    (fuel : Nat) (state : st) (label : info)
    (selected : ndM a info err cs st)
    (outcome : nd_status a err st × List String × st)
    (result : outcome ∈ CerbND.runNDFuel fuel selected state) :
    outcome ∈ CerbND.runNDFuel (fuel + 1)
      (ND (fun initial => (NDnd label [(label, selected)], initial))) state :=
  BranchPath.sound (BranchPath.singleChoice fuel state label selected) result

theorem BranchPath.handlerTransfer {a info err cs st : Type}
    {fuel remaining handlerFuel : Nat}
    {program selected handler : ndM a info err cs st}
    {start selectedState handlerState : st} {path : List Nat}
    {outcome : nd_status a err st × List String × st}
    (branch : BranchPath fuel program start path selected selectedState remaining)
    (transfer : CerbND.runNDFuel remaining selected selectedState =
      CerbND.runNDFuel handlerFuel handler handlerState)
    (handlerResult : outcome ∈ CerbND.runNDFuel handlerFuel handler handlerState) :
    outcome ∈ CerbND.runNDFuel fuel program start := by
  apply BranchPath.sound branch
  rw [transfer]
  exact handlerResult

/-- A small nonvacuous transfer fixture: a selected branch really kills, and
the result survives the branch-to-handler equality rather than appearing only
in a premise. -/
private theorem synthetic_handler_transfer (state : Nat) :
    (Killed state (Other ()), [], state) ∈
      CerbND.runNDFuel 2
        ((ND (fun initial =>
          (NDnd () [((), ND (fun current =>
            (NDkilled (Other ()), current)))], initial))) :
          ndM Unit Unit Unit Unit Nat) state := by
  let handler : ndM Unit Unit Unit Unit Nat :=
    ND (fun current => (NDkilled (Other ()), current))
  exact BranchPath.handlerTransfer
    (BranchPath.singleChoice 1 state () handler) rfl
    (by simp [handler, CerbND.runNDFuel])

/-- The converted live redex contains this exact archived action, including
its operands and polarity. The location alone does not identify an action. -/
inductive OriginalActionRedex : action0 Unit → expr core_run_annotation → Prop where
  | action (annotations : List annot) (pol : polarity)
      (action : action0 Unit) :
      OriginalActionRedex action
        (convert_expr (.Expr annotations (.Eaction (.Paction pol action))))
  | excluded (annotations : List annot) (number : Nat)
      (action : action0 Unit) :
      OriginalActionRedex action
        (convert_expr (.Expr annotations (.Eexcluded number action)))

/-- A positional `get_ctx` witness and the inventory's `nodeAt` address
resolve to the very same action value. This closes the gap where two actions
share a source line or inherited location. -/
theorem initialContext_action_identity {body : expr Unit} {address : List Nat}
    {ctx : context} {redex : expr core_run_annotation}
    (selected : CoreExecution.InitialActionContext body address ctx redex) :
    ∃ action : action0 Unit,
      Operation.nodeAt (.effect body) address = some (.action action) ∧
      OriginalActionRedex action redex := by
  induction selected with
  | action annotations pact =>
      cases pact with
      | Paction pol action =>
          exact ⟨action, rfl, .action annotations pol action⟩
  | excluded annotations number action =>
      exact ⟨action, rfl, .excluded annotations number action⟩
  | unseq annotations expressions index selected tail inner redex position nested ih =>
      obtain ⟨action, node, origin⟩ := ih
      refine ⟨action, ?_, origin⟩
      simpa [Operation.nodeAt, CerbCertifiedInventory.children, position] using node
  | wseq annotations pattern first second tail inner redex nested ih =>
      obtain ⟨action, node, origin⟩ := ih
      refine ⟨action, ?_, origin⟩
      simpa [Operation.nodeAt, CerbCertifiedInventory.children] using node
  | sseq annotations pattern first second tail inner redex nested ih =>
      obtain ⟨action, node, origin⟩ := ih
      refine ⟨action, ?_, origin⟩
      simpa [Operation.nodeAt, CerbCertifiedInventory.children] using node
  | bound annotations body tail inner redex nested ih =>
      obtain ⟨action, node, origin⟩ := ih
      refine ⟨action, ?_, origin⟩
      simpa [Operation.nodeAt, CerbCertifiedInventory.children] using node
  | annotated annotations footprints body tail inner redex nested ih =>
      obtain ⟨action, node, origin⟩ := ih
      refine ⟨action, ?_, origin⟩
      simpa [Operation.nodeAt, CerbCertifiedInventory.children] using node

theorem selectedContext_archived_node {site : SiteRow} {body : expr Unit}
    {address : List Nat} {ctx : context}
    {redex : expr core_run_annotation}
    (root : Inspect.siteRoot site = some (.effect body))
    (selected : CoreExecution.InitialActionContext body address ctx redex) :
    ∃ action : action0 Unit,
      (Inspect.siteRoot site).bind (fun tree => Operation.nodeAt tree address) =
        some (.action action) ∧
      OriginalActionRedex action redex := by
  obtain ⟨action, node, origin⟩ := initialContext_action_identity selected
  exact ⟨action, by simpa only [root, Option.bind_some] using node, origin⟩

inductive AccessKind where
  | load
  | store

/-- These are the request constructors reached by `.Load0` and `.Store0`.
The type check is over the actual request value selected by the reducer. -/
def requestKind : AccessKind → action_request2 thread_state → Prop
  | .load, .LoadRequest2 _ _ _ _ => True
  | .store, .StoreRequest2 _ _ _ _ _ _ => True
  | _, _ => False

def accessReason : AccessKind → kill_reason driver_error → Prop
  | .load, Other (DErr_memory (MerrAccess LoadAccess _)) => True
  | .store, Other (DErr_memory (MerrAccess StoreAccess _)) => True
  | _, _ => False

/-- The archived address selects its own load/store action and source
location. An inherited thread location cannot satisfy this predicate. -/
def ArchivedMemoryAction (snapshot : CoreExecution.Snapshot)
    (site : SiteRow) (address : List Nat) (location : CerbLocation.Loc)
    (kind : AccessKind) : Prop :=
  CoreExecution.ArchivedActionSite snapshot site address location ∧
  match kind with
  | .load => ∃ (ty ptr : pexpr),
      SiteFault.loadAtSite site address = some (location, ty, ptr)
  | .store => ∃ (locking : Bool) (ty ptr value : pexpr)
      (order : memory_order),
      SiteFault.storeAtSite site address =
        some (location, locking, ty, ptr, value, order)

/-- An unchanged archived body supplies the exact live `get_ctx` redex and
`step_ctx` index. The selected subtree of the *actual* `oneRound` ND tree is
the same `process_core_step2` request, with its state and remaining fuel.
The complete outcome list must then equal the chosen load/store handler's
outcomes after request evaluation and fresh action-ID allocation. This
handler transfer is a checked proof obligation, so one coincidentally equal
kill from a different stage cannot be borrowed. -/
def SelectedInitialActionFault [LemFuel] [CerbGlobal.Switches]
    (snapshot : CoreExecution.Snapshot) (site : SiteRow)
    (address : List Nat) (location : CerbLocation.Loc) (kind : AccessKind)
    (before : driver_state) (choices : List Nat)
    (after : driver_state) (reason : kill_reason driver_error)
    (trace : List String) : Prop :=
  ArchivedMemoryAction snapshot site address location kind ∧
  before.core_file = CoreExecution.runtimeFile snapshot ∧
  ∃ (body : expr Unit) (atStep : driver_state)
    (tid : Nat) (parent : Option Nat) (thread : thread_state)
    (ctx : context) (redex : expr core_run_annotation)
    (redexIndex : Nat) (step : core_step2)
    (debug : String) (isUnseq : Bool)
    (requestM : core_runM (action_request2 thread_state))
    (request : action_request2 thread_state)
    (requestState handlerState : driver_state)
    (aid remaining handlerFuel : Nat),
    Inspect.siteRoot site = some (.effect body) ∧
    atStep.core_file = CoreExecution.runtimeFile snapshot ∧
    (tid, (parent, thread)) ∈ atStep.core_state0.thread_states ∧
    CoreExecution.SiteOwnsThread snapshot site atStep thread ∧
    thread.arena = convert_expr body ∧
    (get_ctx thread.arena)[redexIndex]? = some (ctx, redex) ∧
    CoreExecution.InitialActionContext body address ctx redex ∧
    CoreExecution.rawActionLocation redex = some location ∧
    (step_ctx atStep.core_file.enumDefs atStep.core_file.tagDefs
      atStep.layout_state atStep.core_file atStep.core_extern tid
      (parent, thread))[redexIndex]? = some step ∧
    step = .Step_action_request2 debug location tid isUnseq requestM ∧
    CerbND.runND (liftCore_run requestM) atStep =
      [(Active request, [], requestState)] ∧
    CerbND.runND (liftCore_run (runS fresh_action_id')) requestState =
      [(Active aid, [], handlerState)] ∧
    requestKind kind request ∧
    BranchPath LemFuel.fuel (CoreExecution.oneRound snapshot) before choices
      (process_core_step2 atStep.core_file.enumDefs atStep.core_file.tagDefs
        false (fun _ => nd_return ()) step) atStep remaining ∧
    CerbND.runNDFuel remaining
        (process_core_step2 atStep.core_file.enumDefs atStep.core_file.tagDefs
          false (fun _ => nd_return ()) step) atStep =
      CerbND.runNDFuel handlerFuel
        (action_request_sequential2 atStep.core_file.enumDefs
          atStep.core_file.tagDefs location tid aid request) handlerState ∧
    (Killed after reason, trace, after) ∈
      CerbND.runNDFuel handlerFuel
        (action_request_sequential2 atStep.core_file.enumDefs
          atStep.core_file.tagDefs location tid aid request) handlerState ∧
    accessReason kind reason

/-- The selected request's killed outcome belongs to a real driver round.
No source-to-C behavioral equivalence or native SIGSEGV claim is added. -/
theorem SelectedInitialActionFault.sound [LemFuel] [CerbGlobal.Switches]
    (snapshot : CoreExecution.Snapshot) (site : SiteRow)
    (address : List Nat) (location : CerbLocation.Loc) (kind : AccessKind)
    (before : driver_state) (choices : List Nat)
    (after : driver_state) (reason : kill_reason driver_error)
    (trace : List String)
    (certificate : SelectedInitialActionFault snapshot site address location
      kind before choices after reason trace) :
    CoreExecution.RoundFault snapshot before reason trace after ∧
      accessReason kind reason := by
  rcases certificate with ⟨_, beforeFile, body, atStep, tid, parent, thread,
    ctx, redex, redexIndex, step, debug, isUnseq, requestM, request,
    requestState, handlerState, aid, remaining, handlerFuel,
    siteRoot, _, _, _, _, _, sourceContext, _, _, _, _, _, _, selected,
    transfer, killed, classified⟩
  have ⟨archivedAction, _, _⟩ :=
    selectedContext_archived_node siteRoot sourceContext
  have reached := BranchPath.handlerTransfer selected transfer killed
  exact ⟨⟨beforeFile, by
    simpa only [CoreExecution.roundOutcomes, CerbND.runND] using reached⟩,
    classified⟩

/-- Entry anchoring remains an explicit checked premise. The autonomous
producer must synthesize argv, initial filesystem, the indexed rounds, and
the selected request branch; this definition grants none of them. -/
def SelectedFaultFromEntry [LemFuel] [CerbGlobal.Switches]
    (snapshot : CoreExecution.Snapshot) (site : SiteRow)
    (address : List Nat) (location : CerbLocation.Loc) (kind : AccessKind)
    (supply : Nat) (addressSpaceTop : Int) (runDigest : String)
    (filesystem : CerbFS.FsState) : Prop :=
  ∃ argv start indices before choices after reason trace,
    CoreExecution.PreparedMain snapshot supply addressSpaceTop runDigest
      filesystem argv start ∧
    CoreExecution.IndexedRounds snapshot start indices before ∧
    SelectedInitialActionFault snapshot site address location kind before
      choices after reason trace

theorem SelectedFaultFromEntry.sound [LemFuel] [CerbGlobal.Switches]
    (snapshot : CoreExecution.Snapshot) (site : SiteRow)
    (address : List Nat) (location : CerbLocation.Loc) (kind : AccessKind)
    (supply : Nat) (addressSpaceTop : Int) (runDigest : String)
    (filesystem : CerbFS.FsState)
    (certificate : SelectedFaultFromEntry snapshot site address location kind
      supply addressSpaceTop runDigest filesystem) :
    CoreExecution.ReachedRoundFaultFromEntry snapshot supply addressSpaceTop
      runDigest filesystem (accessReason kind) := by
  rcases certificate with ⟨argv, start, indices, before, choices, after,
    reason, trace, prepared, rounds, selected⟩
  obtain ⟨traces, path⟩ := CoreExecution.IndexedRounds.sound snapshot rounds
  obtain ⟨fault, classified⟩ :=
    SelectedInitialActionFault.sound snapshot site address location kind
      before choices after reason trace selected
  exact ⟨argv, start, traces, before, reason, trace, after,
    prepared, path, fault, classified⟩

end SignalSearch.SelectedRequestFault
