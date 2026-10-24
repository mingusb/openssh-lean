import Std.Tactic.BVDecide

/-!
Executable integer serialization and offset guards, translated from portable
OpenSSH V_10_6_P1, commit a8c72b842423f0774f542d3c2197247c3dd28d74:
* sshbuf.h:341-384 (PEEK_U16/U32/U64 and POKE_U16/U32/U64)
* sshbuf-getput-basic.c:98-109 (check_offset)
* ssherr.h (the four error codes returned here).

The offset model selects a platform with 64-bit size_t. Its `ptrValid` input
represents the result of sshbuf_ptr; it does not model pointer validity,
sshbuf_check_sanity, allocation, aliasing, or memory reads/writes. Theorems
prove properties of these Lean definitions, not their equivalence to C or the
behavior of an entire SSH buffer, packet parser, client, or server.

Upstream copyright and license for the translated sshbuf operations:
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

namespace OpenSSH.Wire

abbrev Byte := BitVec 8

/-- Two network-order bytes, corresponding to PEEK_U16. -/
def pack16 (a b : Byte) : BitVec 16 :=
  (a.setWidth 16 <<< 8) ||| b.setWidth 16

/-- Four network-order bytes, corresponding to PEEK_U32. -/
def pack32 (a b c d : Byte) : BitVec 32 :=
  (a.setWidth 32 <<< 24) ||| (b.setWidth 32 <<< 16) |||
  (c.setWidth 32 <<< 8) ||| d.setWidth 32

/-- Eight network-order bytes, corresponding to PEEK_U64. -/
def pack64 (a b c d e f g h : Byte) : BitVec 64 :=
  (a.setWidth 64 <<< 56) ||| (b.setWidth 64 <<< 48) |||
  (c.setWidth 64 <<< 40) ||| (d.setWidth 64 <<< 32) |||
  (e.setWidth 64 <<< 24) ||| (f.setWidth 64 <<< 16) |||
  (g.setWidth 64 <<< 8) ||| h.setWidth 64

/-- POKE_U16's two output bytes, in memory order. -/
def unpack16 (v : BitVec 16) : Byte × Byte :=
  ((v >>> 8).setWidth 8, v.setWidth 8)

/-- POKE_U32's four output bytes, in memory order. -/
def unpack32 (v : BitVec 32) : Byte × Byte × Byte × Byte :=
  ((v >>> 24).setWidth 8, (v >>> 16).setWidth 8,
    (v >>> 8).setWidth 8, v.setWidth 8)

/-- POKE_U64's eight output bytes, in memory order. -/
def unpack64 (v : BitVec 64) : Byte × Byte × Byte × Byte × Byte × Byte × Byte × Byte :=
  ((v >>> 56).setWidth 8, (v >>> 48).setWidth 8,
    (v >>> 40).setWidth 8, (v >>> 32).setWidth 8,
    (v >>> 24).setWidth 8, (v >>> 16).setWidth 8,
    (v >>> 8).setWidth 8, v.setWidth 8)

theorem unpack16_pack16 (a b : Byte) : unpack16 (pack16 a b) = (a, b) := by
  simp only [unpack16, pack16, Prod.mk.injEq]
  bv_decide

theorem unpack32_pack32 (a b c d : Byte) : unpack32 (pack32 a b c d) = (a, b, c, d) := by
  simp only [unpack32, pack32, Prod.mk.injEq]
  bv_decide

theorem unpack64_pack64 (a b c d e f g h : Byte) :
    unpack64 (pack64 a b c d e f g h) = (a, b, c, d, e, f, g, h) := by
  simp only [unpack64, pack64, Prod.mk.injEq]
  bv_decide

theorem pack16_unpack16 (v : BitVec 16) :
    pack16 (unpack16 v).1 (unpack16 v).2 = v := by
  simp only [pack16, unpack16]
  bv_decide

theorem pack32_unpack32 (v : BitVec 32) :
    pack32 (unpack32 v).1 (unpack32 v).2.1
      (unpack32 v).2.2.1 (unpack32 v).2.2.2 = v := by
  simp only [pack32, unpack32]
  bv_decide

theorem pack64_unpack64 (v : BitVec 64) :
    pack64 (unpack64 v).1 (unpack64 v).2.1
      (unpack64 v).2.2.1 (unpack64 v).2.2.2.1
      (unpack64 v).2.2.2.2.1 (unpack64 v).2.2.2.2.2.1
      (unpack64 v).2.2.2.2.2.2.1 (unpack64 v).2.2.2.2.2.2.2 = v := by
  simp only [pack64, unpack64]
  bv_decide

/-- The selected ABI's SIZE_MAX; every arithmetic operation below is 64-bit. -/
def sizeMax : BitVec 64 := 0xffffffffffffffff

/-- The exact upstream guard is >=, including the non-wrapping sum SIZE_MAX. -/
def offsetRejected (offset len : BitVec 64) : Bool :=
  decide (offset ≥ sizeMax - len)

/-- Numeric portion of check_offset, with upstream check ordering and codes. -/
def checkOffset (ptrValid write : Bool) (bufferLen offset len : BitVec 64) : Int :=
  if !ptrValid then -1
  else if offsetRejected offset len then -10
  else if offset + len > bufferLen then
    if write then -9 else -3
  else 0

/-- Widening to 65 bits exposes the exact mathematical threshold without wrap. -/
theorem offsetRejected_iff_widened_sum (offset len : BitVec 64) :
    offsetRejected offset len = true ↔
      offset.setWidth 65 + len.setWidth 65 ≥ sizeMax.setWidth 65 := by
  simp only [offsetRejected, sizeMax]
  bv_decide

/-- Accepted arithmetic cannot wrap, independently of the buffer length. -/
theorem offsetAccepted_no_wrap (offset len : BitVec 64)
    (h : offsetRejected offset len = false) : offset ≤ offset + len := by
  simp only [offsetRejected, sizeMax] at h
  bv_decide

/-- If addition does wrap then check_offset's first numeric guard rejects it. -/
theorem wrapped_sum_rejected (offset len : BitVec 64)
    (h : offset + len < offset) : offsetRejected offset len = true := by
  simp only [offsetRejected, sizeMax]
  bv_decide

/-- The exact-SIZE_MAX boundary is rejected, though the sum has not wrapped. -/
theorem maximum_sum_rejected (len : BitVec 64) :
    offsetRejected (sizeMax - len) len = true := by
  simp only [offsetRejected, sizeMax]
  bv_decide

/-- Accepted sums stay strictly below SIZE_MAX, not merely at or below it. -/
theorem offsetAccepted_below_max (offset len : BitVec 64)
    (h : offsetRejected offset len = false) : offset + len < sizeMax := by
  simp only [offsetRejected, sizeMax] at *
  bv_decide

/-- Invalid pointers take priority over all numeric conditions. -/
theorem checkOffset_invalid_pointer (write : Bool) (bufferLen offset len : BitVec 64) :
    checkOffset false write bufferLen offset len = -1 := by
  simp [checkOffset]

/-- A rejected numeric range returns INVALID_ARGUMENT before the bounds check. -/
theorem checkOffset_rejected (write : Bool) (bufferLen offset len : BitVec 64)
    (h : offsetRejected offset len = true) :
    checkOffset true write bufferLen offset len = -10 := by
  simp [checkOffset, h]

/-- An empty access at offset zero succeeds, for every representable buffer size. -/
theorem checkOffset_empty (write : Bool) (bufferLen : BitVec 64) :
    checkOffset true write bufferLen 0 0 = 0 := by
  simp [checkOffset, offsetRejected, sizeMax]

end OpenSSH.Wire
