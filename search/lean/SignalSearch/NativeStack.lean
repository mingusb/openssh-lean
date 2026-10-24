import Lean

/-! Arithmetic facts for hash-pinned native stack observations. These facts
describe recorded addresses and an explicit reservation model. They do not
derive an operating-system signal or a C/Core correspondence theorem. -/

namespace SignalSearch.NativeStack

/-- A later stack pointer is lower than the pointer sampled at the first
entry to the same function in the same native process. -/
def ObservedGrowth (firstRsp laterRsp : Nat) : Prop := laterRsp < firstRsp

theorem positiveDrop {firstRsp laterRsp : Nat}
    (growth : ObservedGrowth firstRsp laterRsp) :
    0 < firstRsp - laterRsp := by
  exact Nat.sub_pos_of_lt growth

/-- Arithmetic checks for one observed stack trace. The numbers are supplied
by a separately validated native debugger record. `frames - 1` excludes the
faulting frame, whose prologue had not completed its reservation. -/
def NearLimit (firstRsp fatalRsp softLimit frameBytes frames : Nat) : Prop :=
  fatalRsp < firstRsp ∧
  firstRsp - fatalRsp ≤ softLimit ∧
  (frames - 1) * frameBytes ≤ firstRsp - fatalRsp ∧
  softLimit - (firstRsp - fatalRsp) < frameBytes

/-- The explicit reservation model cannot fit all frames within the supplied
available budget. This is a separate, conditional machine-resource claim. -/
def ReservationShortfall (available frameBytes frames : Nat) : Prop :=
  available < frames * frameBytes

theorem shortfall_of_measured {available frameBytes frames : Nat}
    (measured : available < frames * frameBytes) :
    ReservationShortfall available frameBytes frames := measured

end SignalSearch.NativeStack
