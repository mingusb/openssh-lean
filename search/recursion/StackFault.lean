import Lean

/-!
A deliberately small stack-reservation model for the pinned native scp
witness. The arithmetic and transition theorem are kernel checked. Native
SIGSEGV, the protocol-to-recursion relation, and source/ELF correspondence
are separate proof obligations. This module never executes archived OpenSSH.
-/

namespace RecursionSearch.StackFault

/-- Whether processing depth consecutive nested calls would attempt a stack
reservation larger than the remaining budget. The first insufficient push
halts the abstract machine. This does not itself classify an OS signal. -/
def reserveFault (frameBytes : Nat) : Nat → Nat → Bool
  | _, 0 => false
  | available, depth + 1 =>
      if available < frameBytes then true
      else reserveFault frameBytes (available - frameBytes) depth

/-- A run that demands more reserved bytes than the available stack cannot
complete every push in the explicit stack-reservation transition model. -/
theorem reserveFault_of_shortfall (frameBytes available depth : Nat)
    (shortfall : available < depth * frameBytes) :
    reserveFault frameBytes available depth = true := by
  induction depth generalizing available with
  | zero =>
      simp at shortfall
  | succ depth ih =>
      by_cases cannotPush : available < frameBytes
      · simp [reserveFault, cannotPush]
      · have enough : frameBytes ≤ available := Nat.le_of_not_gt cannotPush
        have remainingShortfall : available - frameBytes < depth * frameBytes := by
          have expanded : available < depth * frameBytes + frameBytes := by
            simpa [Nat.succ_mul] using shortfall
          omega
        simpa [reserveFault, cannotPush] using
          ih (available - frameBytes) remainingShortfall

/-- The exact ten bytes written by the Bash reproducer for each directory
record, expressed without text encoding assumptions. -/
def directoryRecord : List UInt8 := [68, 48, 55, 48, 48, 32, 48, 32, 120, 10]

def witnessInput : Nat → List UInt8
  | 0 => []
  | depth + 1 => directoryRecord ++ witnessInput depth

theorem directoryRecord_length : directoryRecord.length = 10 := by decide

theorem witnessInput_length (depth : Nat) :
    (witnessInput depth).length = depth * 10 := by
  induction depth with
  | zero => rfl
  | succ depth ih =>
      simp [witnessInput, directoryRecord_length, ih, Nat.succ_mul, Nat.add_comm]

/-- The pinned ELF prologue contains sub rsp,0x1000 and then
sub rsp,0x188, a total reservation of 4488 bytes per entered sink frame.
The byte-to-instruction and every-record-to-frame arguments are external
obligations; only this numeric fact is proved here. -/
def scpReservedBytes : Nat := 4096 + 392

def observedSoftStackLimitBytes : Nat := 8192 * 1024

def witnessRecordCount : Nat := 2048

theorem scp_reservation_exceeds_soft_limit :
    observedSoftStackLimitBytes < witnessRecordCount * scpReservedBytes := by
  decide

theorem scp_abstract_stack_fault_if_depth_exceeds (depth available : Nat)
    (withinSoftLimit : available ≤ observedSoftStackLimitBytes)
    (depthShortfall : observedSoftStackLimitBytes < depth * scpReservedBytes) :
    reserveFault scpReservedBytes available depth = true := by
  apply reserveFault_of_shortfall
  omega

theorem scp_abstract_stack_fault_for_any_budget (available : Nat)
    (withinSoftLimit : available ≤ observedSoftStackLimitBytes) :
    reserveFault scpReservedBytes available witnessRecordCount = true := by
  exact scp_abstract_stack_fault_if_depth_exceeds witnessRecordCount available
    withinSoftLimit scp_reservation_exceeds_soft_limit

theorem scp_witness_input_length :
    (witnessInput witnessRecordCount).length = 20480 := by
  simpa [witnessRecordCount] using witnessInput_length 2048

end RecursionSearch.StackFault
