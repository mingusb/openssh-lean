#!/usr/bin/env python3
"""Cerberus CPP adapter for already-preprocessed, hash-bound input.

Cerberus adds its own -D/-include options to the CPP command. They deliberately
have no effect here: the input is the exact output of the reference compiler's
preprocessor, not source to be preprocessed again with Cerberus's libc headers.
"""
from pathlib import Path
import sys

literal_fixture = "--literal-fixture" in sys.argv[1:-1]
preprocessed_link = "--preprocessed-link" in sys.argv[1:-1]
input_path = Path(sys.argv[-1])
# The normal OCaml driver dispatches only .c files. The checked replay gives it
# a private .c symlink to the original hash-bound .i, preserving all input bytes
# and the TU digest without modifying OpenSSH or preprocessing a second time.
if preprocessed_link:
    if literal_fixture or input_path.suffix != ".c" or not input_path.is_symlink():
        raise SystemExit("Expected a preprocessed .c symlink")
    input_path = input_path.resolve(strict=True)
expected_suffix = ".c" if literal_fixture else ".i"
if len(sys.argv) < 2 or input_path.suffix != expected_suffix:
    raise SystemExit(f"Expected one final {expected_suffix} input")
data = input_path.read_bytes()
# A test-only path proves that compiler builtins do not depend on Cerberus's
# forced headers. It accepts only directive-free literal C fixtures; the
# source-census path remains strict .i input with exact byte passthrough.
if literal_fixture and any(line.lstrip().startswith(b"#") for line in data.splitlines()):
    raise SystemExit("Literal fixtures cannot contain preprocessing directives")
sys.stdout.buffer.write(data)
