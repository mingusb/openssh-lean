import SignalSearch.Inspect

open CerbCertifiedInventory
open CerbMem CerberusImpl

namespace SignalSearch.SiteFault

/-- Select a load by the exact structural address of any archived executable
Core row: function, standard-library, global, or implementation. -/
def loadAtSite (site : SiteRow) (address : List Nat) :
    Option (CerbLocation.Loc × pexpr × pexpr) :=
  match (Inspect.siteRoot site).bind (fun root => Operation.nodeAt root address) with
  | some (.action (.Action location () (.Load0 typeExpr pointerExpr _))) =>
      some (location, typeExpr, pointerExpr)
  | _ => none

/-- An exact archived load in any expression-bearing section has a conditional
local null-pointer fault under the actual Core action reducer. Operand values
and entry reachability are hypotheses, and this is not an OS signal theorem. -/
def NullLoadPotential (site : SiteRow) (address : List Nat) : Prop :=
  ∃ (location : CerbLocation.Loc) (typeExpr pointerExpr : pexpr),
    loadAtSite site address = some (location, typeExpr, pointerExpr) ∧
    ∀ [LemFuel] [CerbGlobal.Switches]
      (enums : EnumDefs) (tags : Memory.TagDefs) (state : MemState)
      (expressionAnnotations : List annot) (actionAnnotations : core_run_annotation)
      (evaluate : pexpr → core_runM value) (excluded : Option Nat)
      (order : memory_order) (ty : ctype),
      act_valueFromPexpr typeExpr = some (.Vctype ty) →
      act_valueFromPexpr pointerExpr =
        some (.Vobject (.OVpointer (.PV .Prov_none (.PVnull ty)))) →
      Operation.LoadRequestFault enums tags state (MerrAccess LoadAccess NullPtr)
        (step_action enums tags expressionAnnotations evaluate excluded
          (.Action location actionAnnotations (.Load0 typeExpr pointerExpr order)))

theorem nullLoadPotential_of_site (site : SiteRow) (address : List Nat)
    (selectedSite : (loadAtSite site address).isSome = true) :
    NullLoadPotential site address := by
  unfold NullLoadPotential
  cases selected : loadAtSite site address with
  | none => simp [selected] at selectedSite
  | some triple =>
      rcases triple with ⟨location, typeExpr, pointerExpr⟩
      refine ⟨location, typeExpr, pointerExpr, rfl, ?_⟩
      intro _ _ enums tags state expressionAnnotations actionAnnotations
        evaluate excluded order ty typeValue pointerValue
      exact Operation.load_request_fault enums tags state
        (MerrAccess LoadAccess NullPtr) location
        expressionAnnotations actionAnnotations evaluate excluded
        typeExpr pointerExpr order ty (.PV .Prov_none (.PVnull ty))
        typeValue pointerValue
        (Memory.load_null enums tags location ty state)


/-- The original store operands at an exact address in any expression-bearing
Core row. This selector does not execute or evaluate those operands. -/
def storeAtSite (site : SiteRow) (address : List Nat) :
    Option (CerbLocation.Loc × Bool × pexpr × pexpr × pexpr × memory_order) :=
  match (Inspect.siteRoot site).bind (fun root => Operation.nodeAt root address) with
  | some (.action (.Action location ()
      (.Store0 locking typeExpr pointerExpr valueExpr order))) =>
      some (location, locking, typeExpr, pointerExpr, valueExpr, order)
  | _ => none

/-- A store request faults in the real Cerberus memory operation. The typed
value precondition is essential: an ill-typed value is rejected earlier. -/
def StoreRequestFault [LemFuel] (enums : EnumDefs) (tags : Memory.TagDefs)
    (state : MemState) (fault : mem_error) : action_step → Prop
  | .ACTION_REQUEST _ location
      (.StoreRequest2 _ ty locking pointer value _) =>
      Memory.StopsWith (storeM enums tags location ty locking pointer value)
        state fault location
  | _ => False

/-- Source-grounded null-store potential. The request premise records that
operand evaluation and value conversion reached this exact memory request;
it is not inferred merely from syntax. Entry reachability and OS delivery
remain separate obligations. -/
def NullStorePotential (site : SiteRow) (address : List Nat) : Prop :=
  ∃ (location : CerbLocation.Loc) (locking : Bool)
    (typeExpr pointerExpr valueExpr : pexpr) (order : memory_order),
    storeAtSite site address =
      some (location, locking, typeExpr, pointerExpr, valueExpr, order) ∧
    ∀ [LemFuel] [CerbGlobal.Switches]
      (enums : EnumDefs) (tags : Memory.TagDefs) (state : MemState)
      (expressionAnnotations : List annot) (actionAnnotations : core_run_annotation)
      (evaluate : pexpr → core_runM value) (excluded : Option Nat)
      (ty : ctype) (cvalue : value) (mvalue : MemValue),
      act_valueFromPexpr typeExpr = some (.Vctype ty) →
      act_valueFromPexpr pointerExpr =
        some (.Vobject (.OVpointer (.PV .Prov_none (.PVnull ty)))) →
      act_valueFromPexpr valueExpr = some cvalue →
      memValueFromValue enums tags
        (Ctype ([] : List annot) (unatomic_ ty)) cvalue = some mvalue →
      memValueHasType ty mvalue = true →
      (∃ (continuation : aid → CerbMem.Footprint → expr core_run_annotation),
        step_action enums tags expressionAnnotations evaluate excluded
          (.Action location actionAnnotations
            (.Store0 locking typeExpr pointerExpr valueExpr order)) =
        .ACTION_REQUEST "StoreRequest" location
          (.StoreRequest2 order ty locking
            (.PV .Prov_none (.PVnull ty)) mvalue continuation)) →
      StoreRequestFault enums tags state (MerrAccess StoreAccess NullPtr)
        (step_action enums tags expressionAnnotations evaluate excluded
          (.Action location actionAnnotations
            (.Store0 locking typeExpr pointerExpr valueExpr order)))

theorem nullStorePotential_of_site (site : SiteRow) (address : List Nat)
    (selectedSite : (storeAtSite site address).isSome = true) :
    NullStorePotential site address := by
  unfold NullStorePotential
  cases selected : storeAtSite site address with
  | none => simp [selected] at selectedSite
  | some values =>
      rcases values with ⟨location, locking, typeExpr, pointerExpr,
        valueExpr, order⟩
      refine ⟨location, locking, typeExpr, pointerExpr, valueExpr, order,
        rfl, ?_⟩
      intro _ _ enums tags state expressionAnnotations actionAnnotations
        evaluate excluded ty cvalue mvalue typeValue pointerValue
        valueValue converted typed requested
      rcases requested with ⟨continuation, request⟩
      simp only [request, StoreRequestFault]
      exact Memory.store_null enums tags location ty locking mvalue state typed

end SignalSearch.SiteFault
