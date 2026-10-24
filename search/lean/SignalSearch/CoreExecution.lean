import SignalSearch.Operation
import SignalSearch.Inspect
import SignalSearch.Reachability
import CerbCoreQuote
import CerbND
import Driver

/-!
The archived `CoreSnapshot` is a value, not a replacement operational model.
`runtimeFile` converts that exact value with Cerberus's own conversion. The
query below begins at the production driver's original `main` entry; it does
not grant an arbitrary intermediate state to the search.
-/

namespace SignalSearch.CoreExecution

abbrev Snapshot := CerbCoreQuote.CoreSnapshot

def runtimeFile (snapshot : Snapshot) : file core_run_annotation :=
  convert_file snapshot.toFile

/-- The driver's original entry state, with its symbol supply, address-space
bound, run digest, and filesystem state explicit. -/
def entry (snapshot : Snapshot) (supply : Nat) (addressSpaceTop : Int)
    (runDigest : String) (filesystem : CerbFS.FsState) : driver_state :=
  (initial_driver_state supply addressSpaceTop runDigest
    (runtimeFile snapshot) filesystem).1

/-- The actual Cerberus driver result for an argument vector. This is a pure
proposition-facing definition; compiling this file does not execute a saved
OpenSSH program. -/
def runMain [LemFuel] [CerbGlobal.Switches] (snapshot : Snapshot)
    (supply : Nat) (addressSpaceTop : Int) (runDigest : String)
    (filesystem : CerbFS.FsState) (argv : List String) :=
  let f := runtimeFile snapshot
  CerbND.runND (drive f.enumDefs f.tagDefs false f argv)
    (entry snapshot supply addressSpaceTop runDigest filesystem)

/-- The driver itself installs this exact main-thread marker after evaluating
global initializers and preparing argc, argv and errno. It is checked here
before stopping the startup probe; no arbitrary intermediate state is admitted. -/
def mainReady (f : file core_run_annotation) (state : driver_state) : Bool :=
  match f.main with
  | none => false
  | some mainSym =>
    state.core_state0.thread_states.any fun (_, (_, thread)) =>
      thread.current_proc_opt == some mainSym &&
      thread.current_loc == CerbLocation.other "Driver.drive"

/-- An internal marker used solely to expose the prepared-main state. This is
not an OpenSSH fault and never qualifies as a discovered signal. -/
def checkpointReason : kill_reason driver_error :=
  Other (DErr_other "signal-search: prepared main checkpoint")

/-- `drive_with_loop` uses its callback both to evaluate global initializers
and to run main. During globals this callback invokes the production driver2;
once the driver installs main, it stops and leaves the state in the ND result.
Thus global initialization is included rather than skipped. -/
def checkpointLoopWhen [LemFuel] [CerbGlobal.Switches]
    (f : file core_run_annotation) (stop : driver_state → Bool)
    (withConcurrency : Bool) : driverM Unit :=
  nd_bind nd_get fun state =>
    if stop state then kill checkpointReason
    else driver2 f.enumDefs f.tagDefs withConcurrency

def checkpointLoop [LemFuel] [CerbGlobal.Switches]
    (f : file core_run_annotation) (withConcurrency : Bool) : driverM Unit :=
  checkpointLoopWhen f (mainReady f) withConcurrency

/-- A prefix probe may stop at a selected global initializer as well as at
main. Until the stop predicate is true, the callback is the original driver2.
The caller must prove the stopped state corresponds to its intended C entry. -/
def probeUntil [LemFuel] [CerbGlobal.Switches] (snapshot : Snapshot)
    (stop : driver_state → Bool) (supply : Nat) (addressSpaceTop : Int)
    (runDigest : String) (filesystem : CerbFS.FsState) (argv : List String) :=
  let f := runtimeFile snapshot
  CerbND.runND
    (drive_with_loop f.enumDefs f.tagDefs (checkpointLoopWhen f stop) false false f argv)
    (entry snapshot supply addressSpaceTop runDigest filesystem)

def ReachedProbeState [LemFuel] [CerbGlobal.Switches] (snapshot : Snapshot)
    (stop : driver_state → Bool) (supply : Nat) (addressSpaceTop : Int)
    (runDigest : String) (filesystem : CerbFS.FsState) (argv : List String)
    (state : driver_state) : Prop :=
  stop state = true ∧
  ∃ trace : List String,
    (Killed state checkpointReason, trace, state) ∈
      probeUntil snapshot stop supply addressSpaceTop runDigest filesystem argv

/-- A pure query over the production driver's startup prefix. This definition
does not execute a translated OpenSSH program during compilation. -/
def startupProbe [LemFuel] [CerbGlobal.Switches] (snapshot : Snapshot)
    (supply : Nat) (addressSpaceTop : Int) (runDigest : String)
    (filesystem : CerbFS.FsState) (argv : List String) :=
  let f := runtimeFile snapshot
  CerbND.runND
    (drive_with_loop f.enumDefs f.tagDefs (checkpointLoop f) false false f argv)
    (entry snapshot supply addressSpaceTop runDigest filesystem)

/-- The checkpoint has actual global-initializer and argv setup evidence. The
synthetic stop is a probe result, not a classified failure. -/
def PreparedMain [LemFuel] [CerbGlobal.Switches] (snapshot : Snapshot)
    (supply : Nat) (addressSpaceTop : Int) (runDigest : String)
    (filesystem : CerbFS.FsState) (argv : List String)
    (state : driver_state) : Prop :=
  mainReady (runtimeFile snapshot) state = true ∧
  ∃ trace : List String,
    (Killed state checkpointReason, trace, state) ∈
      startupProbe snapshot supply addressSpaceTop runDigest filesystem argv

/-- The driver installs a global's converted initializer and records its
symbol in `current_loc` immediately before invoking the evaluation loop. The
archive membership obligation is stated separately in `PreparedGlobal`. -/
def globalInitializerReady (row : GlobalRow) (state : driver_state) : Bool :=
  match row.2 with
  | .GlobalDecl _ => false
  | .GlobalDef _ body =>
    state.core_state0.thread_states.any fun (_, (_, thread)) =>
      thread.exec_loc == ELoc_globals &&
      thread.current_loc ==
        CerbLocation.other ("global(" ++ show_symbol row.1 ++ ")") &&
      thread.arena == convert_expr body

/-- A selected global initializer's actual driver state, after earlier
initializers have run and before this initializer is reduced. -/
def PreparedGlobal [LemFuel] [CerbGlobal.Switches] (snapshot : Snapshot)
    (row : GlobalRow) (supply : Nat) (addressSpaceTop : Int)
    (runDigest : String) (filesystem : CerbFS.FsState) (argv : List String)
    (state : driver_state) : Prop :=
  row ∈ snapshot.globs ∧
  ReachedProbeState snapshot (globalInitializerReady row)
    supply addressSpaceTop runDigest filesystem argv state

/-- A fault from the original `main` entry on a concrete argument vector.
The caller chooses the fault predicate. In particular, a memory-model kill is
not silently reclassified as an operating-system SIGSEGV. -/
def MainFault [LemFuel] [CerbGlobal.Switches] (snapshot : Snapshot)
    (supply : Nat) (addressSpaceTop : Int) (runDigest : String)
    (filesystem : CerbFS.FsState) (argv : List String)
    (wanted : kill_reason driver_error → Prop) : Prop :=
  ∃ (after : driver_state) (reason : kill_reason driver_error)
      (trace : List String),
    (Killed after reason, trace, after) ∈
      runMain snapshot supply addressSpaceTop runDigest filesystem argv ∧
    wanted reason

/-- A non-checkpoint failure during the actual global-initializer and main
argument setup prefix. The marker injected at the prepared-main boundary is
excluded from findings. This is still a model outcome, not a native signal. -/
def StartupFault [LemFuel] [CerbGlobal.Switches] (snapshot : Snapshot)
    (supply : Nat) (addressSpaceTop : Int) (runDigest : String)
    (filesystem : CerbFS.FsState) (argv : List String)
    (wanted : kill_reason driver_error → Prop) : Prop :=
  ∃ (after : driver_state) (reason : kill_reason driver_error)
      (trace : List String),
    (Killed after reason, trace, after) ∈
      startupProbe snapshot supply addressSpaceTop runDigest filesystem argv ∧
    reason ≠ checkpointReason ∧ wanted reason

/-- Bind a site to its exact typed row in one of the four expression-bearing
sections. Other Core sections remain in the runtime file and affect execution,
but have no syntactic expression root of this kind. -/
def ArchivedSite (snapshot : Snapshot) (site : SiteRow) : Prop :=
  match site with
  | .function origin row =>
      (origin = "funs" ∧ row ∈ snapshot.funs) ∨
      (origin = "stdlib" ∧ row ∈ snapshot.stdlib)
  | .global row => row ∈ snapshot.globs
  | .implementation row => row ∈ snapshot.impl0

/-- A row-relative address selects an action carrying its own source location.
An inherited ancestor location is insufficient for this source identity. -/
def ArchivedActionSite (snapshot : Snapshot) (site : SiteRow)
    (address : List Nat) (location : CerbLocation.Loc) : Prop :=
  ArchivedSite snapshot site ∧
  ∃ root body,
    Inspect.siteRoot site = some root ∧
    Operation.nodeAt root address = some (.action (.Action location () body))

/-- Exactly one cycle of the production scheduler and request handler. The
continuation ends the cycle; subsequent cycles are represented by `Path`.
This preserves the driver's nondeterministic branch choice. -/
def oneRound [LemFuel] [CerbGlobal.Switches]
    (snapshot : Snapshot) : driverM Unit :=
  let f := runtimeFile snapshot
  driver2_step f.enumDefs f.tagDefs
    (new_drive_core_threads f.enumDefs f.tagDefs)
    (fun _ => nd_return ()) false

def Advances [LemFuel] [CerbGlobal.Switches] (snapshot : Snapshot)
    (before : driver_state) (trace : List String) (after : driver_state) : Prop :=
  before.core_file = runtimeFile snapshot ∧
  after.core_file = runtimeFile snapshot ∧
  (Active (), trace, after) ∈ CerbND.runND (oneRound snapshot) before

def RoundFault [LemFuel] [CerbGlobal.Switches] (snapshot : Snapshot)
    (before : driver_state) (reason : kill_reason driver_error)
    (trace : List String) (after : driver_state) : Prop :=
  before.core_file = runtimeFile snapshot ∧
  (Killed after reason, trace, after) ∈ CerbND.runND (oneRound snapshot) before

/-- Actual successor enumeration from one driver state; no invented transition
relation or function-local approximation is substituted for `driver2_step`. -/
def roundOutcomes [LemFuel] [CerbGlobal.Switches] (snapshot : Snapshot)
    (before : driver_state) :=
  CerbND.runND (oneRound snapshot) before

/-- One nondeterministic branch index per actual driver round is enough to
resume or recheck a path after a worker restart. Each selected outcome must
still be proved to be the corresponding list element; an index alone is not
a reachability certificate. -/
inductive IndexedRounds [LemFuel] [CerbGlobal.Switches]
    (snapshot : Snapshot) : driver_state → List Nat → driver_state → Prop where
  | nil (state : driver_state) : IndexedRounds snapshot state [] state
  | cons {before next finish : driver_state} {index : Nat}
      {indices : List Nat} {trace : List String}
      (beforeFile : before.core_file = runtimeFile snapshot)
      (nextFile : next.core_file = runtimeFile snapshot)
      (selected : (roundOutcomes snapshot before)[index]? =
        some (Active (), trace, next))
      (remaining : IndexedRounds snapshot next indices finish) :
      IndexedRounds snapshot before (index :: indices) finish

theorem IndexedRounds.sound [LemFuel] [CerbGlobal.Switches]
    (snapshot : Snapshot) {start finish : driver_state} {indices : List Nat}
    (walk : IndexedRounds snapshot start indices finish) :
    ∃ traces : List (List String), Path (Advances snapshot) start traces finish := by
  induction walk with
  | nil state => exact ⟨[], .nil state⟩
  | cons beforeFile nextFile selected remaining ih =>
    obtain ⟨traces, rest⟩ := ih
    have chosen := List.mem_of_getElem? selected
    exact ⟨_ :: traces, .cons ⟨beforeFile, nextFile, chosen⟩ rest⟩

/-- Exact-state deduplication can ignore the immutable Core file while
retaining every mutable driver-state field. Hashes or Boolean comparisons can
be used only as lookup hints; equality of these keys is the proof obligation. -/
def mutableStateKey (state : driver_state) : driver_state :=
  { state with core_file := default }

theorem mutableStateKey_restore (state : driver_state) :
    { mutableStateKey state with core_file := state.core_file } = state := by
  cases state
  rfl

theorem same_state_of_key [LemFuel] [CerbGlobal.Switches]
    (snapshot : Snapshot) (left right : driver_state)
    (leftFile : left.core_file = runtimeFile snapshot)
    (rightFile : right.core_file = runtimeFile snapshot)
    (sameKey : mutableStateKey left = mutableStateKey right) :
    left = right := by
  have sameFile : left.core_file = right.core_file := leftFile.trans rightFile.symm
  calc
    left = { mutableStateKey left with core_file := left.core_file } :=
      (mutableStateKey_restore left).symm
    _ = { mutableStateKey right with core_file := right.core_file } := by
      rw [sameKey, sameFile]
    _ = right := mutableStateKey_restore right

theorem active_round_evidence [LemFuel] [CerbGlobal.Switches]
    (snapshot : Snapshot) (before after : driver_state) (trace : List String)
    (beforeFile : before.core_file = runtimeFile snapshot)
    (afterFile : after.core_file = runtimeFile snapshot)
    (selected : (Active (), trace, after) ∈ roundOutcomes snapshot before) :
    Advances snapshot before trace after := by
  exact ⟨beforeFile, afterFile, selected⟩

theorem killed_round_evidence [LemFuel] [CerbGlobal.Switches]
    (snapshot : Snapshot) (before after : driver_state) (trace : List String)
    (reason : kill_reason driver_error)
    (beforeFile : before.core_file = runtimeFile snapshot)
    (selected : (Killed after reason, trace, after) ∈ roundOutcomes snapshot before) :
    RoundFault snapshot before reason trace after := by
  exact ⟨beforeFile, selected⟩

def IndexedRoundFault [LemFuel] [CerbGlobal.Switches]
    (snapshot : Snapshot) (before : driver_state) (index : Nat)
    (reason : kill_reason driver_error) (trace : List String)
    (after : driver_state) : Prop :=
  before.core_file = runtimeFile snapshot ∧
  (roundOutcomes snapshot before)[index]? = some (Killed after reason, trace, after)

theorem IndexedRoundFault.sound [LemFuel] [CerbGlobal.Switches]
    (snapshot : Snapshot) (before : driver_state) (index : Nat)
    (reason : kill_reason driver_error) (trace : List String)
    (after : driver_state)
    (selected : IndexedRoundFault snapshot before index reason trace after) :
    RoundFault snapshot before reason trace after := by
  exact killed_round_evidence snapshot before after trace reason selected.1
    (List.mem_of_getElem? selected.2)

/-- A main-body fault searched in rounds is anchored to global initialization,
argument setup, and the exact main entry of the selected Core snapshot. -/
def ReachedRoundFaultFromEntry [LemFuel] [CerbGlobal.Switches]
    (snapshot : Snapshot) (supply : Nat) (addressSpaceTop : Int)
    (runDigest : String) (filesystem : CerbFS.FsState)
    (wanted : kill_reason driver_error → Prop) : Prop :=
  ∃ argv start traces before reason faultTrace after,
    PreparedMain snapshot supply addressSpaceTop runDigest filesystem argv start ∧
    Path (Advances snapshot) start traces before ∧
    RoundFault snapshot before reason faultTrace after ∧ wanted reason

/-- Durable branch-index evidence for a main-body fault. The input and branch
choices may be persisted; rechecking replays the actual startup and rounds. -/
def IndexedFaultFromEntry [LemFuel] [CerbGlobal.Switches]
    (snapshot : Snapshot) (supply : Nat) (addressSpaceTop : Int)
    (runDigest : String) (filesystem : CerbFS.FsState)
    (wanted : kill_reason driver_error → Prop) : Prop :=
  ∃ argv start indices before index reason faultTrace after,
    PreparedMain snapshot supply addressSpaceTop runDigest filesystem argv start ∧
    IndexedRounds snapshot start indices before ∧
    IndexedRoundFault snapshot before index reason faultTrace after ∧ wanted reason

theorem IndexedFaultFromEntry.sound [LemFuel] [CerbGlobal.Switches]
    (snapshot : Snapshot) (supply : Nat) (addressSpaceTop : Int)
    (runDigest : String) (filesystem : CerbFS.FsState)
    (wanted : kill_reason driver_error → Prop)
    (candidate : IndexedFaultFromEntry snapshot supply addressSpaceTop
      runDigest filesystem wanted) :
    ReachedRoundFaultFromEntry snapshot supply addressSpaceTop
      runDigest filesystem wanted := by
  obtain ⟨argv, start, indices, before, index, reason, faultTrace, after,
    prepared, path, fault, classified⟩ := candidate
  obtain ⟨traces, reached⟩ := IndexedRounds.sound snapshot path
  exact ⟨argv, start, traces, before, reason, faultTrace, after,
    prepared, reached,
    IndexedRoundFault.sound snapshot before index reason faultTrace after fault,
    classified⟩

/-- The unmodified Core reducer supplies one candidate step for each
`get_ctx` redex. This extracts the source location owned by the selected
dynamic action, before the driver's library-location fallback. -/
def rawActionLocation : expr core_run_annotation → Option CerbLocation.Loc
  | .Expr _ (.Eaction (.Paction _ (.Action location _ _))) => some location
  | .Expr _ (.Eexcluded _ (.Action location _ _)) => some location
  | _ => none

/-- Identify a fault by the exact live redex and its matching `step_ctx`
index. This prevents a faulting step from being joined to an unrelated
same-location redex. The archived row/address origin remains a separate proof
obligation because the current reducer does not carry structural provenance. -/
def DynamicRedexFault [LemFuel] [CerbGlobal.Switches]
    (snapshot : Snapshot) (state : driver_state) (redexIndex : Nat)
    (ownLocation : CerbLocation.Loc)
    (wanted : kill_reason driver_error → Prop) : Prop :=
  state.core_file = runtimeFile snapshot ∧
  ∃ (tid : Nat) (parent : Option Nat) (thread : thread_state)
      (ctx : context) (redex : expr core_run_annotation)
      (step : core_step2) (after : driver_state)
      (reason : kill_reason driver_error) (trace : List String),
    (tid, (parent, thread)) ∈ state.core_state0.thread_states ∧
    (get_ctx thread.arena)[redexIndex]? = some (ctx, redex) ∧
    rawActionLocation redex = some ownLocation ∧
    (step_ctx state.core_file.enumDefs state.core_file.tagDefs
      state.layout_state state.core_file state.core_extern tid
      (parent, thread))[redexIndex]? = some step ∧
    (match step with
      | .Step_action_request2 _ _ actualTid _ _ => actualTid = tid
      | _ => False) ∧
    (Killed after reason, trace, after) ∈
      CerbND.runND
        (process_core_step2 state.core_file.enumDefs state.core_file.tagDefs
          false (fun _ => nd_return ()) step) state ∧
    wanted reason

/-- A positional source-to-runtime context certificate for an action selected
before the original body has been rewritten. The context encodes the exact
sibling position, so two equal actions (including actions on the same source
line) cannot be exchanged. Only constructs into which `get_ctx` descends are
present; other constructs require a later provenance-preserving step proof. -/
inductive InitialActionContext :
    expr Unit → List Nat → context → expr core_run_annotation → Prop where
  | action (annotations : List annot) (pact : paction Unit) :
      InitialActionContext (.Expr annotations (.Eaction pact)) [0] .CTX
        (convert_expr (.Expr annotations (.Eaction pact)))
  | excluded (annotations : List annot) (number : Nat) (act : action0 Unit) :
      InitialActionContext (.Expr annotations (.Eexcluded number act)) [0] .CTX
        (convert_expr (.Expr annotations (.Eexcluded number act)))
  | unseq (annotations : List annot) (expressions : List (expr Unit))
      (index : Nat) (selected : expr Unit) (tail : List Nat)
      (inner : context) (redex : expr core_run_annotation)
      (_at : expressions[index]? = some selected)
      (_nested : InitialActionContext selected tail inner redex) :
      InitialActionContext (.Expr annotations (.Eunseq expressions))
        (index :: tail)
        (.Cunseq annotations
          ((expressions.take index).map convert_expr) inner
          ((expressions.drop (index + 1)).map convert_expr)) redex
  | wseq (annotations : List annot) (pattern : pattern)
      (first second : expr Unit) (tail : List Nat)
      (inner : context) (redex : expr core_run_annotation)
      (_nested : InitialActionContext first tail inner redex) :
      InitialActionContext (.Expr annotations (.Ewseq pattern first second))
        (0 :: tail) (.Cwseq annotations pattern inner (convert_expr second)) redex
  | sseq (annotations : List annot) (pattern : pattern)
      (first second : expr Unit) (tail : List Nat)
      (inner : context) (redex : expr core_run_annotation)
      (_nested : InitialActionContext first tail inner redex) :
      InitialActionContext (.Expr annotations (.Esseq pattern first second))
        (0 :: tail) (.Csseq annotations pattern inner (convert_expr second)) redex
  | bound (annotations : List annot) (body : expr Unit) (tail : List Nat)
      (inner : context) (redex : expr core_run_annotation)
      (_nested : InitialActionContext body tail inner redex) :
      InitialActionContext (.Expr annotations (.Ebound body))
        (0 :: tail) (.Cbound annotations inner) redex
  | annotated (annotations : List annot) (footprints : List dyn_annotation)
      (body : expr Unit) (tail : List Nat)
      (inner : context) (redex : expr core_run_annotation)
      (_nested : InitialActionContext body tail inner redex) :
      InitialActionContext (.Expr annotations (.Eannot footprints body))
        (0 :: tail) (.Cannot annotations footprints inner) redex

/-- Confirm that the live thread selected this archived body, not a different
body with identical syntax. Function lookup follows the driver's stdlib-first
resolution; the funs case is deliberately restricted to an unshadowed direct
symbol. A global requires a unique position for its symbol in the snapshot. -/
private def lookupSymbol {α : Type} (symbol : sym) (values : Fmap sym α) : Option α :=
  fmapLookupBy (fun a b => Lem_Basic_classes.ordCompare a b) symbol values

def SiteOwnsThread (snapshot : Snapshot) (site : SiteRow)
    (state : driver_state) (thread : thread_state) : Prop :=
  match site with
  | .function origin (symbol, .Proc loc marker bTy params body) =>
      thread.current_proc_opt = some symbol ∧
      if origin = "stdlib" then
        thread.stack0 ≠ Stack_empty ∧
        lookupSymbol symbol state.core_file.stdlib =
          some (.Proc loc marker bTy params (convert_expr body))
      else if origin = "funs" then
        lookupSymbol symbol state.core_file.stdlib = none ∧
        resolve_linked_function state.core_extern symbol = symbol ∧
        lookupSymbol symbol state.core_file.funs =
          some (.Proc loc marker bTy params (convert_expr body))
      else False
  | .global (symbol, .GlobalDef bTy body) =>
      thread.exec_loc = ELoc_globals ∧
      thread.current_loc =
        CerbLocation.other ("global(" ++ show_symbol symbol ++ ")") ∧
      ∃ ordinal, snapshot.globs[ordinal]? = some (symbol, GlobalDef bTy body) ∧
        ∀ (index : Nat) (other : GlobalRow), snapshot.globs[index]? = some other →
          other.1 = symbol → index = ordinal
  | .implementation _ => False
  | _ => False

/-- Exact archived action identity for the first reducible operation in an
unchanged body. The same `get_ctx` result and `step_ctx` index lead to the
request-handler kill. This is intentionally narrower than a general dynamic
origin theorem: after reduction rewrites the arena, provenance must be carried
through those reductions before an archived address can be claimed. -/
def ExactInitialBodyFault [LemFuel] [CerbGlobal.Switches]
    (snapshot : Snapshot) (site : SiteRow) (address : List Nat)
    (ownLocation : CerbLocation.Loc) (state : driver_state)
    (redexIndex : Nat) (wanted : kill_reason driver_error → Prop) : Prop :=
  ArchivedActionSite snapshot site address ownLocation ∧
  ∃ (body : expr Unit) (tid : Nat) (parent : Option Nat)
      (thread : thread_state) (ctx : context)
      (redex : expr core_run_annotation) (step : core_step2)
      (after : driver_state) (reason : kill_reason driver_error)
      (trace : List String),
    Inspect.siteRoot site = some (.effect body) ∧
    state.core_file = runtimeFile snapshot ∧
    (tid, (parent, thread)) ∈ state.core_state0.thread_states ∧
    SiteOwnsThread snapshot site state thread ∧
    thread.arena = convert_expr body ∧
    (get_ctx thread.arena)[redexIndex]? = some (ctx, redex) ∧
    InitialActionContext body address ctx redex ∧
    rawActionLocation redex = some ownLocation ∧
    (step_ctx state.core_file.enumDefs state.core_file.tagDefs
      state.layout_state state.core_file state.core_extern tid
      (parent, thread))[redexIndex]? = some step ∧
    (match step with
      | .Step_action_request2 _ _ actualTid _ _ => actualTid = tid
      | _ => False) ∧
    (Killed after reason, trace, after) ∈
      CerbND.runND
        (process_core_step2 state.core_file.enumDefs state.core_file.tagDefs
          false (fun _ => nd_return ()) step) state ∧
    wanted reason

theorem ExactInitialBodyFault.dynamic [LemFuel] [CerbGlobal.Switches]
    (snapshot : Snapshot) (site : SiteRow) (address : List Nat)
    (ownLocation : CerbLocation.Loc) (state : driver_state)
    (redexIndex : Nat) (wanted : kill_reason driver_error → Prop)
    (fault : ExactInitialBodyFault snapshot site address ownLocation state
      redexIndex wanted) :
    DynamicRedexFault snapshot state redexIndex ownLocation wanted := by
  obtain ⟨_, body, tid, parent, thread, ctx, redex, step, after, reason, trace,
    _, stateFile, threadMember, _, _, selectedRedex, _, location, selectedStep,
    actionStep, killed, wantedReason⟩ := fault
  exact ⟨stateFile, tid, parent, thread, ctx, redex, step, after, reason, trace,
    threadMember, selectedRedex, location, selectedStep, actionStep, killed,
    wantedReason⟩

/-- The same dynamic fault relation covers an initializer reached by the
driver's global-startup prefix, without assuming main has begun. -/
def ReachedDynamicFaultFromGlobal [LemFuel] [CerbGlobal.Switches]
    (snapshot : Snapshot) (row : GlobalRow)
    (supply : Nat) (addressSpaceTop : Int) (runDigest : String)
    (filesystem : CerbFS.FsState) (wanted : kill_reason driver_error → Prop) : Prop :=
  ∃ argv start traces current index location,
    PreparedGlobal snapshot row supply addressSpaceTop runDigest filesystem argv start ∧
    Path (Advances snapshot) start traces current ∧
    DynamicRedexFault snapshot current index location wanted

end SignalSearch.CoreExecution
