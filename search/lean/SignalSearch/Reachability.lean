import Lean

namespace SignalSearch

/-- The relation supplied by the query determines the semantics, including
memory, external effects and platform events. Observations need not be signals. -/
inductive Path {State Event : Type} (step : State → Event → State → Prop) :
    State → List Event → State → Prop where
  | nil (s : State) : Path step s [] s
  | cons {s t u : State} {e : Event} {es : List Event} :
      step s e t → Path step t es u → Path step s (e :: es) u

/-- The user predicate may constrain inputs, the complete trace, and final state.
There is no distinguished signal-generation mechanism or path-length parameter. -/
def Elicits {Input State Event : Type}
    (initial : Input → State → Prop) (step : State → Event → State → Prop)
    (wanted : Input → List Event → State → Prop) : Prop :=
  ∃ input start events finish,
    initial input start ∧ Path step start events finish ∧ wanted input events finish

theorem Path.append {State Event : Type} {step : State → Event → State → Prop}
    {s t u : State} {xs ys : List Event}
    (first : Path step s xs t) (second : Path step t ys u) :
    Path step s (xs ++ ys) u := by
  induction first with
  | nil => exact second
  | cons edge _ ih => exact .cons edge (ih second)

end SignalSearch
