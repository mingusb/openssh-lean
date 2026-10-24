import Std

/-!
Framework for matching observable effects under a common environment input stream.
This is NOT an OpenSSH reference semantics. No instance connecting the C source to
the Lean model is supplied. Infinite traces, fairness, timing distributions and
divergence need additional obligations, listed in CONFORMANCE.md.
-/
namespace OpenSSH.Refinement

abbrev Bytes := List UInt8

/-- Observation vocabulary, not an implemented operating-system adapter. Numeric
identifiers and timestamps must have a specified interpretation in each profile. -/
inductive Effect where
  | networkWrite (fd : Nat) (bytes : Bytes)
  | fileWrite (path : Bytes) (offset : Nat) (bytes : Bytes)
  | fileMetadata (path : Bytes) (mode uid gid : Nat)
  | fileRemove (path : Bytes)
  | fileRename (source destination : Bytes)
  | stdout (bytes : Bytes)
  | stderr (bytes : Bytes)
  | log (facility severity : Nat) (bytes : Bytes)
  | spawn (pid : Nat) (executable : Bytes) (argv env : List Bytes)
  | signal (pid number : Nat)
  | privilege (uid gid : Nat) (groups : List Nat)
  | terminal (fd : Nat) (operation : Bytes) (arguments : Bytes)
  | clock (nanoseconds : Nat)
  | exit (status : Int)
  | platform (operation arguments result : Bytes)
  deriving Repr, DecidableEq

/-- Environment inputs must record results, errors and external nondeterminism;
the machine may not secretly call IO while being reasoned about. -/
inductive Input where
  | networkRead (fd : Nat) (bytes : Bytes)
  | endOfFile (fd : Nat)
  | random (bytes : Bytes)
  | clock (nanoseconds : Nat)
  | signal (number : Nat)
  | scheduling (process : Nat)
  | allocation (success : Bool)
  | platformResult (operation arguments result : Bytes) (errno : Int)
  deriving Repr, DecidableEq

/-- A deterministic, total, input-driven component. Internal divergence and
partial/environment-enabled transitions must be modeled before using this for
the entire program. One external input is not assumed to be one OS syscall. -/
structure Machine (State : Type) where
  initial : State
  step : State → Input → State × List Effect

def run (machine : Machine S) (state : S) : List Input → S × List Effect
  | [] => (state, [])
  | input :: rest =>
    let (next, emitted) := machine.step state input
    let (last, later) := run machine next rest
    (last, emitted ++ later)

/-- Explicit lockstep obligations; the relation cannot be chosen empty because
the initial states must be related. This is a sufficient contract for finite,
input-driven traces, not yet a C/Lean whole-program equivalence certificate. -/
structure Correspondence (reference : Machine R) (model : Machine M) where
  related : R → M → Prop
  initial : related reference.initial model.initial
  step : ∀ r m input, related r m →
    (reference.step r input).2 = (model.step m input).2 ∧
    related (reference.step r input).1 (model.step m input).1

theorem run_corresponds (reference : Machine R) (model : Machine M)
    (certificate : Correspondence reference model)
    (inputs : List Input) (r : R) (m : M)
    (h : certificate.related r m) :
    (run reference r inputs).2 = (run model m inputs).2 ∧
    certificate.related (run reference r inputs).1 (run model m inputs).1 := by
  induction inputs generalizing r m with
  | nil => exact ⟨rfl, h⟩
  | cons input rest ih =>
    have hs := certificate.step r m input h
    have hr := ih (reference.step r input).1 (model.step m input).1 hs.2
    exact ⟨by simp only [run, hs.1, hr.1], hr.2⟩

theorem initial_traces_equal (reference : Machine R) (model : Machine M)
    (certificate : Correspondence reference model) (inputs : List Input) :
    (run reference reference.initial inputs).2 =
      (run model model.initial inputs).2 :=
  (run_corresponds reference model certificate inputs _ _ certificate.initial).1

/-- Safety transfer is conditional on an actual correspondence certificate.
It is not evidence that the current buffer model represents OpenSSH. -/
theorem transfer_trace_property (reference : Machine R) (model : Machine M)
    (certificate : Correspondence reference model)
    (property : List Effect → Prop)
    (model_safe : ∀ inputs, property (run model model.initial inputs).2) :
    ∀ inputs, property (run reference reference.initial inputs).2 := by
  intro inputs
  rw [initial_traces_equal reference model certificate inputs]
  exact model_safe inputs

end OpenSSH.Refinement
