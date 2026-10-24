import OpenSSH

/- Differential-test interface only. This is not an ssh or sshd replacement. -/
open OpenSSH.Buffer

def hexNibble (c : Char) : Option Nat :=
  if '0' ≤ c && c ≤ '9' then some (c.toNat - '0'.toNat)
  else if 'a' ≤ c && c ≤ 'f' then some (c.toNat - 'a'.toNat + 10)
  else if 'A' ≤ c && c ≤ 'F' then some (c.toNat - 'A'.toNat + 10)
  else none

def decodeHexChars : List Char → Option Bytes
  | [] => some []
  | a :: b :: rest => do
      let hi ← hexNibble a
      let lo ← hexNibble b
      let tail ← decodeHexChars rest
      pure (UInt8.ofNat (16 * hi + lo) :: tail)
  | _ => none

def decodeHex (s : String) : Option Bytes :=
  if s == "_" || s == "-" then some [] else decodeHexChars s.toList

def hexChar (n : Nat) : Char :=
  Char.ofNat (if n < 10 then '0'.toNat + n else 'a'.toNat + n - 10)

def encodeHex (bytes : Bytes) : String :=
  if bytes.isEmpty then "_"
  else String.ofList (bytes.flatMap fun b =>
    [hexChar (b.toNat / 16), hexChar (b.toNat % 16)])

def showNatOption (n : Option Nat) : String :=
  n.map toString |>.getD "-"

def showStringResult (r : StringResult) : String :=
  s!"{r.code} {encodeHex r.buffer} {r.value.map encodeHex |>.getD "-"} {showNatOption r.length}"

def showIntegerResult (r : IntegerResult) : String :=
  s!"{r.code} {encodeHex r.buffer} {showNatOption r.value} -"

def handleLine (line : String) : Except String String := do
  let parts := line.splitOn " " |>.filter (· != "")
  let [op, hex, valueFlag, lengthFlag, allocationFlag, previousText] := parts
    | throw "expected six fields"
  let some bytes := decodeHex hex | throw "invalid hexadecimal input"
  unless [valueFlag, lengthFlag, allocationFlag].all (fun f => f == "0" || f == "1") do
    throw "invalid flag"
  let previous ← if previousText == "-" then pure none else
    match previousText.toNat? with
    | some n => pure (some n)
    | none => throw "invalid previous value"
  let wantValue := valueFlag == "1"
  let wantLength := lengthFlag == "1"
  let allocSuccess := allocationFlag == "1"
  let width := match op with
    | "u8" => 8 | "u16" => 16 | "u32" => 32 | "u64" => 64 | _ => 0
  if width != 0 then
    if let some n := previous then
      unless n < 2 ^ width do throw "previous value outside C integer width"
  match op with
  | "u8" => pure (showIntegerResult (getU8 bytes previous))
  | "u16" => pure (showIntegerResult (getU16 bytes previous))
  | "u32" => pure (showIntegerResult (getU32 bytes previous))
  | "u64" => pure (showIntegerResult (getU64 bytes previous))
  | "peek" => pure (showStringResult (peekStringDirect bytes wantValue wantLength))
  | "direct" => pure (showStringResult (getStringDirect bytes wantValue wantLength))
  | "string" => pure (showStringResult (getString bytes wantValue wantLength allocSuccess))
  | "cstring" => pure (showStringResult (getCString bytes wantValue wantLength allocSuccess))
  | _ => throw "unknown operation"

def main (args : List String) : IO UInt32 := do
  if args == ["--self-test"] then
    for (label, passed) in boundaryTests do
      unless passed do
        IO.eprintln s!"FAIL: {label}"
        return 1
    IO.println s!"PASS: {boundaryTests.length} boundary cases"
    return 0
  unless args.isEmpty do
    IO.eprintln "usage: conformance [--self-test]; otherwise reads the differential line protocol"
    return 2
  let input ← IO.getStdin
  let output ← IO.getStdout
  repeat
    let raw ← input.getLine
    if raw.isEmpty then break
    let line := raw.trimAscii.toString
    if line.isEmpty then continue
    match handleLine line with
    | .ok response => output.putStrLn response
    | .error error =>
        IO.eprintln s!"invalid test input: {error}"
        return 2
  return 0
