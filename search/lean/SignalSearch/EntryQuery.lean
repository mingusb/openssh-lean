import SignalSearch.CoreExecution
import SignalSearch.SnapshotImport

namespace SignalSearch.EntryQuery

/-- A driver kill caused by the Core memory model's access check. This does
not identify an operating-system signal; native evidence and a platform
correspondence argument are separate. -/
def memoryAccessReason : kill_reason driver_error → Prop
  | .Other (.DErr_memory (.MerrAccess _ _)) => True
  | _ => False

/-- A generated, fault-specific query for an exact saved model. The archive
fixes fuel, semantic switches, symbol supply, address-space bound, and run
digest. The witness still has to establish startup, concrete input, each
selected scheduler round, and the memory-access kill. -/
def memoryAccessFromEntry (input : SavedCoreProofInput) : Prop :=
  letI : LemFuel := ⟨input.fuel⟩
  letI : CerbGlobal.Switches := ⟨[.gnu_pointer_conversions]⟩
  ∃ filesystem : CerbFS.FsState,
    CoreExecution.IndexedFaultFromEntry input.core input.supply
      input.addressSpaceTop input.executionDigest filesystem memoryAccessReason

/-- Discharging the generated indexed query yields an actual driver path from
the saved model's entry; the model memory-access classification is retained. -/
def reachedMemoryAccessFromEntry (input : SavedCoreProofInput) : Prop :=
  letI : LemFuel := ⟨input.fuel⟩
  letI : CerbGlobal.Switches := ⟨[.gnu_pointer_conversions]⟩
  ∃ filesystem : CerbFS.FsState,
    CoreExecution.ReachedRoundFaultFromEntry input.core input.supply
      input.addressSpaceTop input.executionDigest filesystem memoryAccessReason

theorem memoryAccessFromEntry.sound (input : SavedCoreProofInput)
    (certificate : memoryAccessFromEntry input) :
    reachedMemoryAccessFromEntry input := by
  letI : LemFuel := ⟨input.fuel⟩
  letI : CerbGlobal.Switches := ⟨[.gnu_pointer_conversions]⟩
  dsimp [memoryAccessFromEntry, reachedMemoryAccessFromEntry] at *
  obtain ⟨filesystem, checked⟩ := certificate
  exact ⟨filesystem, CoreExecution.IndexedFaultFromEntry.sound
    input.core input.supply input.addressSpaceTop input.executionDigest
    filesystem memoryAccessReason checked⟩

end SignalSearch.EntryQuery
