import SignalSearch.EntryQuery

namespace SignalSearch.SeedEntryQuery

/-- An archived driver path with a fixed C argument vector. The input includes
`argv[0]`; the native probe records its executable path separately from its
remaining arguments. The filesystem is still a witness to be constructed, so
this proposition alone does not identify native stdin or environment bytes. -/
def indexedFaultForArgv (input : SavedCoreProofInput) (argv : List String)
    (wanted : kill_reason driver_error → Prop) : Prop :=
  letI : LemFuel := ⟨input.fuel⟩
  letI : CerbGlobal.Switches := ⟨[.gnu_pointer_conversions]⟩
  ∃ (filesystem : CerbFS.FsState) (start before after : driver_state)
    (indices : List Nat) (index : Nat)
    (reason : kill_reason driver_error) (faultTrace : List String),
    CoreExecution.PreparedMain input.core input.supply input.addressSpaceTop
      input.executionDigest filesystem argv start ∧
    CoreExecution.IndexedRounds input.core start indices before ∧
    CoreExecution.IndexedRoundFault input.core before index reason faultTrace
      after ∧ wanted reason

/-- Generic model-driver kill on the native seed's exact textual argv. The
kernel checks the driver path; a C signal correspondence is not inferred. -/
def driverFaultForArgv (input : SavedCoreProofInput) (argv : List String) : Prop :=
  indexedFaultForArgv input argv (fun _ => True)

/-- A model memory-access kill on the native seed's exact textual argv. This
is a useful SIGSEGV hypothesis, not an assertion about the native fault. -/
def memoryAccessForArgv (input : SavedCoreProofInput) (argv : List String) : Prop :=
  indexedFaultForArgv input argv EntryQuery.memoryAccessReason

/-- A reached driver fault that continues to name the same fixed argv.
Keeping the input in this conclusion permits later native-input comparison. -/
def reachedFaultForArgv (input : SavedCoreProofInput) (argv : List String)
    (wanted : kill_reason driver_error → Prop) : Prop :=
  letI : LemFuel := ⟨input.fuel⟩
  letI : CerbGlobal.Switches := ⟨[.gnu_pointer_conversions]⟩
  ∃ (filesystem : CerbFS.FsState) (start before after : driver_state)
    (traces : List (List String))
    (reason : kill_reason driver_error) (faultTrace : List String),
    CoreExecution.PreparedMain input.core input.supply input.addressSpaceTop
      input.executionDigest filesystem argv start ∧
    Path (CoreExecution.Advances input.core) start traces before ∧
    CoreExecution.RoundFault input.core before reason faultTrace after ∧
    wanted reason

theorem indexedFaultForArgv.sound (input : SavedCoreProofInput)
    (argv : List String) (wanted : kill_reason driver_error → Prop)
    (candidate : indexedFaultForArgv input argv wanted) :
    reachedFaultForArgv input argv wanted := by
  letI : LemFuel := ⟨input.fuel⟩
  letI : CerbGlobal.Switches := ⟨[.gnu_pointer_conversions]⟩
  dsimp [indexedFaultForArgv] at candidate
  obtain ⟨filesystem, start, before, after, indices, index, reason,
    faultTrace, prepared, rounds, fault, classified⟩ := candidate
  obtain ⟨traces, path⟩ := CoreExecution.IndexedRounds.sound input.core rounds
  exact ⟨filesystem, start, before, after, traces, reason, faultTrace,
    prepared, path,
    CoreExecution.IndexedRoundFault.sound input.core before index reason
      faultTrace after fault, classified⟩

theorem reachedFaultForArgv.followsEntry (input : SavedCoreProofInput)
    (argv : List String) (wanted : kill_reason driver_error → Prop)
    (reached : reachedFaultForArgv input argv wanted) :
    letI : LemFuel := ⟨input.fuel⟩
    letI : CerbGlobal.Switches := ⟨[.gnu_pointer_conversions]⟩
    ∃ filesystem : CerbFS.FsState,
      CoreExecution.ReachedRoundFaultFromEntry input.core input.supply
        input.addressSpaceTop input.executionDigest filesystem wanted := by
  letI : LemFuel := ⟨input.fuel⟩
  letI : CerbGlobal.Switches := ⟨[.gnu_pointer_conversions]⟩
  dsimp [reachedFaultForArgv] at reached
  obtain ⟨filesystem, start, before, after, traces, reason, faultTrace,
    prepared, path, fault, classified⟩ := reached
  exact ⟨filesystem, argv, start, traces, before, reason, faultTrace,
    after, prepared, path, fault, classified⟩

end SignalSearch.SeedEntryQuery
