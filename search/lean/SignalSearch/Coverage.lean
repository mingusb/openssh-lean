import SignalSearch.Inspect
import CerbCoreQuote

/-!
Complete typed-expression coverage for the current Core data representation.
This theorem concerns the executable expression trees in a `CoreSnapshot`.
It makes no assertion about C translation preservation, path reachability,
external effects, or operating-system signal delivery.
-/

open CerbCertifiedInventory

namespace SignalSearch.Coverage

/-- The body-bearing records in the four selected Core snapshot sections.
The other eight fields remain part of the snapshot and execution semantics;
the claim that they have no additional executable body roots is a separate
schema audit, not a consequence of this definition alone. -/
def siteRows (snapshot : CerbCoreQuote.CoreSnapshot) : List SiteRow :=
  (snapshot.funs.map (SiteRow.function "funs")) ++
  (snapshot.stdlib.map (SiteRow.function "stdlib")) ++
  (snapshot.globs.map SiteRow.global) ++
  (snapshot.impl0.map SiteRow.implementation)

theorem funs_in_siteRows (snapshot : CerbCoreQuote.CoreSnapshot)
    (row : FunctionRow) (member : row ∈ snapshot.funs) :
    SiteRow.function "funs" row ∈ siteRows snapshot := by
  simp [siteRows, member]

theorem stdlib_in_siteRows (snapshot : CerbCoreQuote.CoreSnapshot)
    (row : FunctionRow) (member : row ∈ snapshot.stdlib) :
    SiteRow.function "stdlib" row ∈ siteRows snapshot := by
  simp [siteRows, member]

theorem global_in_siteRows (snapshot : CerbCoreQuote.CoreSnapshot)
    (row : GlobalRow) (member : row ∈ snapshot.globs) :
    SiteRow.global row ∈ siteRows snapshot := by
  simp [siteRows, member]

theorem implementation_in_siteRows (snapshot : CerbCoreQuote.CoreSnapshot)
    (row : ImplementationRow) (member : row ∈ snapshot.impl0) :
    SiteRow.implementation row ∈ siteRows snapshot := by
  simp [siteRows, member]

/-- `extract` is the producer's total traversal, already proved exact against
its inductive Core syntax occurrence relation. -/
def rowNodes (row : SiteRow) : List Node :=
  match Inspect.siteRoot row with
  | none => []
  | some root => extract root

def snapshotNodes (snapshot : CerbCoreQuote.CoreSnapshot) : List Node :=
  (siteRows snapshot).flatMap rowNodes

theorem rowNodes_exact (row : SiteRow) (node : Node) :
    node ∈ rowNodes row ↔
      ∃ root, Inspect.siteRoot row = some root ∧ Occurs root node := by
  unfold rowNodes
  cases h : Inspect.siteRoot row with
  | none => simp
  | some root => simp [extract_exact]

/-- Every node in each expression-bearing record occurs in the resulting
snapshot inventory, and every listed node comes from one such record. -/
theorem snapshotNodes_exact (snapshot : CerbCoreQuote.CoreSnapshot) (node : Node) :
    node ∈ snapshotNodes snapshot ↔
      ∃ row ∈ siteRows snapshot,
        ∃ root, Inspect.siteRoot row = some root ∧ Occurs root node := by
  unfold snapshotNodes
  constructor
  · intro present
    obtain ⟨row, member, nested⟩ := List.mem_flatMap.mp present
    obtain ⟨root, selected, occurrence⟩ := (rowNodes_exact row node).mp nested
    exact ⟨row, member, root, selected, occurrence⟩
  · rintro ⟨row, member, root, selected, occurrence⟩
    apply List.mem_flatMap.mpr
    exact ⟨row, member, (rowNodes_exact row node).mpr
      ⟨root, selected, occurrence⟩⟩

/-- A semantic subterm always has a stable structural address, including when
the same Core value appears at several distinct positions. -/
private theorem member_has_index {α : Type} {xs : List α} {x : α}
    (member : x ∈ xs) : ∃ index : Nat, xs[index]? = some x := by
  induction xs with
  | nil => simp at member
  | cons first rest ih =>
    rcases List.mem_cons.mp member with equal | tail
    · subst x
      exact ⟨0, rfl⟩
    · obtain ⟨index, selected⟩ := ih tail
      exact ⟨index + 1, by simpa using selected⟩

theorem occurrence_has_address {root node : Node}
    (occurrence : Occurs root node) :
    ∃ address, Operation.nodeAt root address = some node := by
  induction occurrence with
  | here _ => exact ⟨[], rfl⟩
  | @descend parent child found immediate _ ih =>
    obtain ⟨index, childAt⟩ := member_has_index
      ((immediate_iff_mem parent child).mp immediate)
    obtain ⟨tail, foundAt⟩ := ih
    exact ⟨index :: tail, by
      simp only [Operation.nodeAt, childAt, Option.bind_some, foundAt]⟩

theorem address_exact (root node : Node) :
    (∃ address, Operation.nodeAt root address = some node) ↔
      Occurs root node := by
  constructor
  · rintro ⟨address, selected⟩
    exact Operation.nodeAt_occurs selected
  · exact occurrence_has_address

/-- The scanner actually used by `Inspect.sites` enumerates exactly the
producer's independently proved Core extractor, with no dropped or fabricated
expression occurrences. Addresses and location provenance are additional
metadata on this same list. -/
theorem visits_nodes (root : Node) (reversedAddress : List Nat)
    (inherited : Option CerbLocation.Loc) :
    (Inspect.visits root reversedAddress inherited).map Inspect.Visit.node =
      extract root := by
  fun_induction Inspect.visits root reversedAddress inherited with
  | case1 node reverse inherited own location origin ih =>
    simp only [List.map_cons, List.map_flatMap]
    rw [extract]
    congr 1
    calc
      ((children node).attach.zipIdx.flatMap fun pair =>
          (Inspect.visits pair.1.val (pair.2 :: reverse) location).map
            Inspect.Visit.node) =
        ((children node).attach.zipIdx.flatMap fun pair => extract pair.1.val) := by
          congr 1
          funext pair
          exact ih pair
      _ = (((children node).attach.zipIdx.map Prod.fst).flatMap
            (fun child => extract child.val)) := by
          rw [List.flatMap_map]
      _ = (children node).attach.flatMap (fun child => extract child.val) := by
          rw [List.zipIdx_map_fst]

end SignalSearch.Coverage
