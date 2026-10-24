import Std

/-
Selected operations translated from OpenSSH sshbuf-getput-basic.c and constants
from sshbuf.h/ssherr.h. Original notice retained:

Copyright (c) 2011 Damien Miller

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
-/

/-!
# Selected OpenSSH sshbuf reads

Executable model of `sshbuf-getput-basic.c` in the pinned portable source.
This file covers the content-level behavior of sane buffers for the four
unsigned integer consuming reads, peek/get string-direct, get-string, and
get-cstring. Returned copied strings include the extra terminating NUL; their
reported length excludes that extra byte. Direct strings retain exactly their
wire payload, including a possible wire NUL. A missing value denotes NULL.

The input buffer is its unread byte sequence. Allocation success is an explicit
environment input: allocation failure occurs *after* a valid string is consumed.
A NULL destination does not allocate. String outputs are initialized before any
error, whereas integer outputs retain their caller-provided value on error.

Excluded here: the C memory model, pointer identity/lifetime/aliasing, physical
allocation and memory contents outside returned bytes, buffer metadata,
refcounts, sanity-check aborts, concurrent mutation, and diagnostic I/O. The
unreachable consume/skip failures after a successful peek are excluded by the
sane, immutable-input buffer abstraction. These are model definitions and
internal proofs, not a proof of refinement from C or of complete OpenSSH parity.
-/

namespace OpenSSH.Buffer

abbrev Bytes := List UInt8

def allocFail : Int := -2
def messageIncomplete : Int := -3
def invalidFormat : Int := -4
def stringTooLarge : Int := -6
def sizeMax : Nat := 0x8000000

/-- Decode a big-endian sequence without machine-integer overflow. -/
def readBE (bytes : Bytes) : Nat :=
  bytes.foldl (fun acc byte => acc * 256 + byte.toNat) 0

structure IntegerResult where
  code : Int
  buffer : Bytes
  value : Option Nat
  deriving Repr, DecidableEq, BEq

/-- `previous = none` models a NULL output pointer. For C correspondence a
present previous value must fit the selected width; the test adapter checks this.
The generic mathematical helper also accepts other natural numbers. -/
def getUnsigned (width : Nat) (bytes : Bytes)
    (previous : Option Nat := some 0) : IntegerResult :=
  if bytes.length < width then
    ⟨messageIncomplete, bytes, previous⟩
  else
    ⟨0, bytes.drop width, previous.map (fun _ => readBE (bytes.take width))⟩

def getU8 (bytes : Bytes) (previous : Option Nat := some 0) : IntegerResult :=
  getUnsigned 1 bytes previous

def getU16 (bytes : Bytes) (previous : Option Nat := some 0) : IntegerResult :=
  getUnsigned 2 bytes previous

def getU32 (bytes : Bytes) (previous : Option Nat := some 0) : IntegerResult :=
  getUnsigned 4 bytes previous

def getU64 (bytes : Bytes) (previous : Option Nat := some 0) : IntegerResult :=
  getUnsigned 8 bytes previous

structure StringResult where
  code : Int
  buffer : Bytes
  value : Option Bytes
  length : Option Nat
  deriving Repr, DecidableEq, BEq

/-- All string APIs first set a requested value to NULL and length to zero. -/
def initialized (bytes : Bytes) (wantLength : Bool) (code : Int) : StringResult :=
  ⟨code, bytes, none, if wantLength then some 0 else none⟩

/-- Validation order matches upstream: header, hard maximum, payload. -/
def checkString (bytes : Bytes) : Except Int Nat :=
  if bytes.length < 4 then
    .error messageIncomplete
  else
    let len := readBE (bytes.take 4)
    if len > sizeMax - 4 then
      .error stringTooLarge
    else if bytes.length - 4 < len then
      .error messageIncomplete
    else
      .ok len

def peekStringDirect (bytes : Bytes) (wantValue : Bool := true)
    (wantLength : Bool := true) : StringResult :=
  match checkString bytes with
  | .error code => initialized bytes wantLength code
  | .ok len =>
      ⟨0, bytes, if wantValue then some ((bytes.drop 4).take len) else none,
        if wantLength then some len else none⟩

def getStringDirect (bytes : Bytes) (wantValue : Bool := true)
    (wantLength : Bool := true) : StringResult :=
  match checkString bytes with
  | .error code => initialized bytes wantLength code
  | .ok len =>
      ⟨0, bytes.drop (len + 4),
        if wantValue then some ((bytes.drop 4).take len) else none,
        if wantLength then some len else none⟩

/-- Copy an already consumed direct string, allocating only for non-NULL valp. -/
def allocateCopy (r : StringResult) (allocSuccess : Bool) : StringResult :=
  if r.code != 0 then r
  else
    match r.value with
    | none => r
    | some payload =>
        if allocSuccess then { r with value := some (payload ++ [0]) }
        else { r with code := allocFail, value := none,
                      length := r.length.map (fun _ => 0) }

def getString (bytes : Bytes) (wantValue : Bool := true)
    (wantLength : Bool := true) (allocSuccess : Bool := true) : StringResult :=
  allocateCopy (getStringDirect bytes wantValue wantLength) allocSuccess

/-- The first NUL, if any, must be the final payload byte. -/
def hasEmbeddedNul (payload : Bytes) : Bool := payload.dropLast.contains 0

def getCString (bytes : Bytes) (wantValue : Bool := true)
    (wantLength : Bool := true) (allocSuccess : Bool := true) : StringResult :=
  match checkString bytes with
  | .error code => initialized bytes wantLength code
  | .ok len =>
      if hasEmbeddedNul ((bytes.drop 4).take len) then
        initialized bytes wantLength invalidFormat
      else
        getString bytes wantValue wantLength allocSuccess

theorem getUnsigned_incomplete (width : Nat) (bytes : Bytes) (previous : Option Nat)
    (h : bytes.length < width) :
    getUnsigned width bytes previous = ⟨messageIncomplete, bytes, previous⟩ := by
  simp [getUnsigned, h]

theorem getUnsigned_complete (width : Nat) (bytes : Bytes) (previous : Option Nat)
    (h : ¬bytes.length < width) :
    getUnsigned width bytes previous =
      ⟨0, bytes.drop width, previous.map (fun _ => readBE (bytes.take width))⟩ := by
  simp [getUnsigned, h]

theorem peekStringDirect_preserves_buffer (bytes : Bytes) (wantValue wantLength : Bool) :
    (peekStringDirect bytes wantValue wantLength).buffer = bytes := by
  unfold peekStringDirect
  cases checkString bytes <;> rfl

theorem getStringDirect_error_preserves_buffer (bytes : Bytes)
    (wantValue wantLength : Bool) (code : Int) (h : checkString bytes = .error code) :
    getStringDirect bytes wantValue wantLength = initialized bytes wantLength code := by
  simp [getStringDirect, h]

theorem getStringDirect_success_consumes (bytes : Bytes)
    (wantValue wantLength : Bool) (len : Nat) (h : checkString bytes = .ok len) :
    (getStringDirect bytes wantValue wantLength).buffer = bytes.drop (len + 4) := by
  simp [getStringDirect, h]

/-- Successful validation bounds the decoded length and available input. -/
theorem checkString_success_bounds (bytes : Bytes) (len : Nat)
    (h : checkString bytes = .ok len) :
    4 ≤ bytes.length ∧ len = readBE (bytes.take 4) ∧
      len ≤ sizeMax - 4 ∧ len + 4 ≤ bytes.length := by
  unfold checkString at h
  split at h
  · contradiction
  · rename_i hHeader
    dsimp only at h
    split at h
    · contradiction
    · rename_i hMax
      split at h
      · contradiction
      · rename_i hPayload
        cases h
        exact ⟨by omega, rfl, by omega, by omega⟩

/-- Every successful direct read consumes exactly its header and payload. -/
theorem getStringDirect_success_length (bytes : Bytes)
    (wantValue wantLength : Bool) (len : Nat) (h : checkString bytes = .ok len) :
    (getStringDirect bytes wantValue wantLength).buffer.length + len + 4 = bytes.length := by
  have hBounds := (checkString_success_bounds bytes len h).2.2.2
  simp [getStringDirect, h, List.length_drop]
  omega

/-- A successfully checked payload contains exactly the advertised bytes. -/
theorem checked_payload_length (bytes : Bytes) (len : Nat)
    (h : checkString bytes = .ok len) :
    ((bytes.drop 4).take len).length = len := by
  have hBounds := (checkString_success_bounds bytes len h).2.2.2
  simp only [List.length_take, List.length_drop]
  omega

theorem allocateCopy_preserves_consumed_buffer (r : StringResult) (allocSuccess : Bool) :
    (allocateCopy r allocSuccess).buffer = r.buffer := by
  unfold allocateCopy
  split
  · rfl
  · cases r.value <;> simp
    split <;> rfl

theorem getString_allocation_failure_consumes (bytes : Bytes) (len : Nat)
    (h : checkString bytes = .ok len) :
    getString bytes true true false =
      ⟨allocFail, bytes.drop (len + 4), none, some 0⟩ := by
  simp [getString, getStringDirect, h, allocateCopy]

theorem getString_null_destination_ignores_allocation (bytes : Bytes)
    (wantLength : Bool) (allocSuccess : Bool) :
    getString bytes false wantLength allocSuccess = getStringDirect bytes false wantLength := by
  unfold getString getStringDirect
  cases checkString bytes <;> simp [allocateCopy, initialized]

theorem getCString_invalid_format_preserves_buffer (bytes : Bytes)
    (wantValue wantLength allocSuccess : Bool) (len : Nat)
    (h : checkString bytes = .ok len)
    (hnul : hasEmbeddedNul ((bytes.drop 4).take len) = true) :
    getCString bytes wantValue wantLength allocSuccess =
      initialized bytes wantLength invalidFormat := by
  simp [getCString, h, hnul]

/-- Includes header-boundary, error-precedence, NUL, OOM and NULL-output cases. -/
def boundaryTests : List (String × Bool) :=
  [ ("u8 empty preserves previous", getU8 [] (some 123) == ⟨-3, [], some 123⟩)
  , ("u16 short preserves previous", getU16 [0x12] (some 999) == ⟨-3, [0x12], some 999⟩)
  , ("u32 big endian and remainder", getU32 [1, 2, 3, 4, 9] == ⟨0, [9], some 16909060⟩)
  , ("u64 maximum", getU64 [255, 255, 255, 255, 255, 255, 255, 255] ==
      ⟨0, [], some 18446744073709551615⟩)
  , ("u8 NULL output still consumes", getU8 [4, 5] none == ⟨0, [5], none⟩)
  , ("incomplete header", getString [0, 0, 0] == ⟨-3, [0, 0, 0], none, some 0⟩)
  , ("incomplete payload", getString [0, 0, 0, 2, 7] == ⟨-3, [0, 0, 0, 2, 7], none, some 0⟩)
  , ("limit payload missing", getString [7, 255, 255, 252] ==
      ⟨-3, [7, 255, 255, 252], none, some 0⟩)
  , ("over limit beats incomplete", getString [7, 255, 255, 253] ==
      ⟨-6, [7, 255, 255, 253], none, some 0⟩)
  , ("u32 maximum length rejected", getString [255, 255, 255, 255] ==
      ⟨-6, [255, 255, 255, 255], none, some 0⟩)
  , ("peek leaves payload and tail", peekStringDirect [0, 0, 0, 1, 65, 9] ==
      ⟨0, [0, 0, 0, 1, 65, 9], some [65], some 1⟩)
  , ("direct no terminator", getStringDirect [0, 0, 0, 1, 65, 9] ==
      ⟨0, [9], some [65], some 1⟩)
  , ("copy appends terminator", getString [0, 0, 0, 1, 65, 9] ==
      ⟨0, [9], some [65, 0], some 1⟩)
  , ("empty allocation", getString [0, 0, 0, 0, 9] == ⟨0, [9], some [0], some 0⟩)
  , ("OOM consumes and clears length", getString [0, 0, 0, 1, 65, 9] true true false ==
      ⟨-2, [9], none, some 0⟩)
  , ("NULL output bypasses OOM", getString [0, 0, 0, 1, 65, 9] false true false ==
      ⟨0, [9], none, some 1⟩)
  , ("NULL length remains absent", getString [0, 0, 0, 1, 65, 9] true false ==
      ⟨0, [9], some [65, 0], none⟩)
  , ("CString embedded NUL unchanged", getCString [0, 0, 0, 2, 0, 65, 9] ==
      ⟨-4, [0, 0, 0, 2, 0, 65, 9], none, some 0⟩)
  , ("CString terminal NUL allowed", getCString [0, 0, 0, 2, 65, 0, 9] ==
      ⟨0, [9], some [65, 0, 0], some 2⟩)
  , ("CString repeated NUL rejected", getCString [0, 0, 0, 2, 0, 0, 9] ==
      ⟨-4, [0, 0, 0, 2, 0, 0, 9], none, some 0⟩)
  , ("CString NULL output still validates", getCString [0, 0, 0, 2, 0, 65, 9] false true ==
      ⟨-4, [0, 0, 0, 2, 0, 65, 9], none, some 0⟩)
  , ("CString OOM consumes", getCString [0, 0, 0, 1, 65, 9] true true false ==
      ⟨-2, [9], none, some 0⟩)
  ]

/-- Kernel-checked finite boundary regressions, without native-decision axioms. -/
example : boundaryTests.all (fun test => test.2) = true := by decide

end OpenSSH.Buffer
