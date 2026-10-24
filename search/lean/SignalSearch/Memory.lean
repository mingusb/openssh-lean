import CerbMem

open CerbMem CerberusImpl

namespace SignalSearch.Memory

abbrev TagDefs := CerbTags.TagDefsMap

/-- One memory operation's actual semantic result. This is a Core memory fault;
the platform/compiler connection to an OS signal is a separate obligation. -/
def StopsWith {α : Type} (operation : memM α) (state : MemState)
    (fault : mem_error) (loc : CerbLocation.Loc) : Prop :=
  match operation with
  | ND step => (step state).1 = NDkilled (failReason fault loc)

theorem load_null [LemFuel] [CerbGlobal.Switches]
    (enums : EnumDefs) (tags : TagDefs) (loc : CerbLocation.Loc)
    (ty : ctype) (state : MemState) :
    StopsWith (loadM enums tags loc ty (.PV .Prov_none (.PVnull ty))) state
      (MerrAccess LoadAccess NullPtr) loc := rfl

theorem store_null [LemFuel]
    (enums : EnumDefs) (tags : TagDefs) (loc : CerbLocation.Loc)
    (ty : ctype) (locking : Bool) (value : MemValue) (state : MemState)
    (typed : memValueHasType ty value = true) :
    StopsWith (storeM enums tags loc ty locking (.PV .Prov_none (.PVnull ty)) value) state
      (MerrAccess StoreAccess NullPtr) loc := by
  simp [StopsWith, storeM, typed]

theorem load_function [LemFuel] [CerbGlobal.Switches]
    (enums : EnumDefs) (tags : TagDefs) (loc : CerbLocation.Loc)
    (ty : ctype) (prov : Provenance) (symbol : sym) (state : MemState) :
    StopsWith (loadM enums tags loc ty (.PV prov (.PVfunction symbol))) state
      (MerrAccess LoadAccess FunctionPtr) loc := rfl

theorem store_function [LemFuel]
    (enums : EnumDefs) (tags : TagDefs) (loc : CerbLocation.Loc)
    (ty : ctype) (locking : Bool) (prov : Provenance) (symbol : sym)
    (value : MemValue) (state : MemState) (typed : memValueHasType ty value = true) :
    StopsWith (storeM enums tags loc ty locking (.PV prov (.PVfunction symbol)) value) state
      (MerrAccess StoreAccess FunctionPtr) loc := by
  simp [StopsWith, storeM, typed]

theorem load_without_provenance [LemFuel] [CerbGlobal.Switches]
    (enums : EnumDefs) (tags : TagDefs) (loc : CerbLocation.Loc)
    (ty : ctype) (members : Option UnionSelections) (address : Int) (state : MemState) :
    StopsWith (loadM enums tags loc ty (.PV .Prov_none (.PVconcrete members address))) state
      (MerrAccess LoadAccess OutOfBoundPtr) loc := rfl

theorem store_without_provenance [LemFuel]
    (enums : EnumDefs) (tags : TagDefs) (loc : CerbLocation.Loc)
    (ty : ctype) (locking : Bool) (members : Option UnionSelections) (address : Int)
    (value : MemValue) (state : MemState) (typed : memValueHasType ty value = true) :
    StopsWith (storeM enums tags loc ty locking (.PV .Prov_none (.PVconcrete members address)) value) state
      (MerrAccess StoreAccess OutOfBoundPtr) loc := by
  simp [StopsWith, storeM, typed]

/-- A synthesis query, universally quantified over the real memory state, layouts,
source location, semantic switches and evaluator fuel. Search must produce ptr. -/
def NullLoadQuery : Prop :=
  ∀ [LemFuel] [CerbGlobal.Switches]
    (enums : EnumDefs) (tags : TagDefs) (loc : CerbLocation.Loc)
    (ty : ctype) (state : MemState),
    ∃ ptr, StopsWith (loadM enums tags loc ty ptr) state
      (MerrAccess LoadAccess NullPtr) loc

end SignalSearch.Memory
