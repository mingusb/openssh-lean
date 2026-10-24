import SignalSearch.Fragment
import SignalSearch.Memory
import Core_reduction

open CerbCertifiedInventory
open CerbMem CerberusImpl

namespace SignalSearch.Operation

/-- The body of the exact archived declaration. Declarations without a body have
no root; they are not converted to a successful or empty procedure. -/
def functionRoot (row : FunctionRow) : Option Node :=
  match row.2 with
  | .Fun _ _ body => some (.pure body)
  | .Proc _ _ _ _ body => some (.effect body)
  | _ => none

/-- A stable structural address, using the producer's complete child traversal.
This address is not an execution path. -/
def nodeAt (root : Node) : List Nat → Option Node
  | [] => some root
  | index :: rest => ((children root)[index]?).bind (fun child => nodeAt child rest)

def operationAt (row : FunctionRow) (address : List Nat) : Option Node :=
  (functionRoot row).bind (fun root => nodeAt root address)

theorem nodeAt_occurs {root found : Node} {address : List Nat}
    (selected : nodeAt root address = some found) : Occurs root found := by
  induction address generalizing root with
  | nil =>
    simp only [nodeAt, Option.some.injEq] at selected
    subst found
    exact .here root
  | cons index rest ih =>
    cases lookup : (children root)[index]? with
    | none => simp [nodeAt, lookup] at selected
    | some child =>
      simp only [nodeAt, lookup, Option.bind_some] at selected
      exact .descend ((immediate_iff_mem root child).mpr (List.mem_of_getElem? lookup))
        (ih selected)

/-- The original load operands and location, before symbolic evaluation. -/
def loadAt (row : FunctionRow) (address : List Nat) :
    Option (CerbLocation.Loc × pexpr × pexpr) :=
  match operationAt row address with
  | some (.action (.Action location () (.Load0 typeExpr pointerExpr _))) =>
    some (location, typeExpr, pointerExpr)
  | _ => none

/-- The memory operation requested by the actual Core action reducer. This is
a local semantic condition, not a claim that a program entry reaches the action
or that the platform delivers an OS signal. -/
def LoadRequestFault [LemFuel] [CerbGlobal.Switches]
    (enums : EnumDefs) (tags : Memory.TagDefs) (state : MemState)
    (fault : mem_error) : action_step → Prop
  | .ACTION_REQUEST _ location (.LoadRequest2 _ ty pointer _) =>
    Memory.StopsWith (loadM enums tags location ty pointer) state fault location
  | _ => False

/-- Backward rule for the actual action reducer. Operand evaluation and a memory
fault remain proof obligations; no invented evaluator or successful fallback is
substituted for either. The caller can use any memory-fault predicate instance. -/
theorem load_request_fault [LemFuel] [CerbGlobal.Switches]
    (enums : EnumDefs) (tags : Memory.TagDefs) (state : MemState)
    (fault : mem_error) (location : CerbLocation.Loc)
    (expressionAnnotations : List annot) (actionAnnotations : core_run_annotation)
    (evaluate : pexpr → core_runM value) (excluded : Option Nat)
    (typeExpr pointerExpr : pexpr) (order : memory_order) (ty : ctype) (pointer : PointerValue)
    (typeValue : act_valueFromPexpr typeExpr = some (.Vctype ty))
    (pointerValue : act_valueFromPexpr pointerExpr = some (.Vobject (.OVpointer pointer)))
    (faulting : Memory.StopsWith (loadM enums tags location ty pointer) state fault location) :
    LoadRequestFault enums tags state fault
      (step_action enums tags expressionAnnotations evaluate excluded
        (.Action location actionAnnotations (.Load0 typeExpr pointerExpr order))) := by
  simpa only [step_action, typeValue, pointerValue, LoadRequestFault] using faulting

/-- A source-grounded load site with a conditional local null-load fault.
The selected operation is in the archived row. Operand evaluation, an
entry-to-site path, and any OS signal remain separate proof obligations. -/
def NullLoadPotential (row : FunctionRow) (address : List Nat) : Prop :=
  ∃ (location : CerbLocation.Loc) (typeExpr pointerExpr : pexpr),
    loadAt row address = some (location, typeExpr, pointerExpr) ∧
    ∀ [LemFuel] [CerbGlobal.Switches]
      (enums : EnumDefs) (tags : Memory.TagDefs) (state : MemState)
      (expressionAnnotations : List annot) (actionAnnotations : core_run_annotation)
      (evaluate : pexpr → core_runM value) (excluded : Option Nat)
      (order : memory_order) (ty : ctype),
      act_valueFromPexpr typeExpr = some (.Vctype ty) →
      act_valueFromPexpr pointerExpr =
        some (.Vobject (.OVpointer (.PV .Prov_none (.PVnull ty)))) →
      LoadRequestFault enums tags state (MerrAccess LoadAccess NullPtr)
        (step_action enums tags expressionAnnotations evaluate excluded
          (.Action location actionAnnotations (.Load0 typeExpr pointerExpr order)))

/-- An exact archived load site admits a checked conditional local-fault rule.
This theorem proves no path to the site and makes no native signal claim. -/
theorem nullLoadPotential_of_site (row : FunctionRow) (address : List Nat)
    (site : (loadAt row address).isSome = true) :
    NullLoadPotential row address := by
  unfold NullLoadPotential
  cases selected : loadAt row address with
  | none => simp [selected] at site
  | some triple =>
      rcases triple with ⟨location, typeExpr, pointerExpr⟩
      refine ⟨location, typeExpr, pointerExpr, rfl, ?_⟩
      intro _ _ enums tags state expressionAnnotations actionAnnotations
        evaluate excluded order ty typeValue pointerValue
      exact load_request_fault enums tags state
        (MerrAccess LoadAccess NullPtr) location
        expressionAnnotations actionAnnotations evaluate excluded
        typeExpr pointerExpr order ty (.PV .Prov_none (.PVnull ty))
        typeValue pointerValue (Memory.load_null enums tags location ty state)

end SignalSearch.Operation
