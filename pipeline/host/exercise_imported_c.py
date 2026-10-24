#!/usr/bin/env python3
"""Exercise a whole, mechanically imported OpenSSH C unit inside Cerberus Lean.

The original preprocessed unit is an unchanged byte prefix. Appended C is only
a test harness. Expected arrays come from the native compiler, not a rewritten
implementation. This bounded regression does not test complete X25519 or SSH.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess

SOURCE = "smult_curve25519_ref.c"
CASES = ["add", "add_wrap", "sub", "squeeze", "freeze", "mult", "square", "mult121665"]
DISPATCH = r'''
# 1 "openssh_import_test_harness.c"
static void exercise_case(unsigned int k, unsigned int out[32]) {
  unsigned int a[32], b[32], j;
  for (j = 0; j < 32; j++) {
    a[j] = j + 1;
    b[j] = 31 - j;
    out[j] = 0;
  }
  switch (k) {
    case 0: add(out, a, b); break;
    case 1:
      for (j = 0; j < 32; j++) a[j] = 4294967295U;
      add(out, a, b); break;
    case 2: sub(out, b, a); break;
    case 3:
      for (j = 0; j < 32; j++) out[j] = 65535;
      squeeze(out); break;
    case 4:
      for (j = 0; j < 32; j++) out[j] = 0;
      out[31] = 128; freeze(out); break;
    case 5: mult(out, a, b); break;
    case 6: square(out, a); break;
    case 7: mult121665(out, a); break;
  }
}
'''


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def invoke(argv, out, err, cwd, timeout=None):
    environment = dict(os.environ, LEAN_ABORT_ON_PANIC="1")
    # Nested capped invocations must retain the caller's selected limit.
    environment.setdefault("CERB_MEM_MAX", "none")
    with out.open("wb") as stdout, err.open("wb") as stderr:
        process = subprocess.Popen(argv, cwd=cwd, stdout=stdout, stderr=stderr,
                                   env=environment,
                                   start_new_session=True)
        try:
            process.wait(timeout=timeout)
            return {"arguments": argv, "exit_code": process.returncode, "timeout": False,
                    "stdout_sha256": sha(out), "stderr_sha256": sha(err)}
        except subprocess.TimeoutExpired:
            # Kill this invocation's process group, including interpreter children.
            # Killing just the cgroup wrapper can leave the actual run alive.
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
            return {"arguments": argv, "exit_code": None, "timeout": True,
                    "stdout_sha256": sha(out), "stderr_sha256": sha(err)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--census", type=Path, required=True)
    parser.add_argument("--cerberus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--timeout", type=int, default=0,
                        help="Optional Lean deadline in seconds; 0 disables the deadline")
    args = parser.parse_args()
    census = json.loads(args.census.read_text())
    if census["openssh_commit"] != "a8c72b842423f0774f542d3c2197247c3dd28d74":
        raise ValueError("Wrong OpenSSH pin")
    unit = next(u for u in census["translation_units"] if u["source"] == SOURCE)
    original = Path(unit["preprocessing"]["path"])
    if sha(original) != unit["preprocessing"]["sha256"] or sha(unit["file"]) != unit["source_sha256"]:
        raise ValueError("OpenSSH input bytes changed")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    prefix = original.read_bytes()
    oracle_source = output / "native-oracle.i"
    oracle_source.write_bytes(prefix + DISPATCH.encode() + b'''
extern int printf(const char *, ...);
int main(void) {
  unsigned int k, j, out[32];
  for (k = 0; k < 8; k++) {
    exercise_case(k, out);
    for (j = 0; j < 32; j++) printf("%u\\n", out[j]);
  }
  return 0;
}
''')
    # Preserve the configured compiler flags, substituting only the input/output.
    flags = unit["arguments"][:]
    compiler = flags.pop(0)
    i = flags.index("-o")
    del flags[i:i + 2]
    flags.remove("-c")
    flags = [flag for flag in flags if not flag.endswith(".c")]
    oracle_binary = output / "native-oracle"
    compile_argv = [compiler] + flags + [str(oracle_source), "-o", str(oracle_binary)]
    subprocess.run(compile_argv, cwd=unit["directory"], capture_output=True, check=True, timeout=None)
    native = subprocess.run([str(oracle_binary)], capture_output=True, check=True, timeout=None)
    (output / "native-arrays.txt").write_bytes(native.stdout)
    expected = [int(s) for s in native.stdout.splitlines()]
    if len(expected) != 256 or native.stderr or any(n < 0 or n >= 2 ** 32 for n in expected):
        raise ValueError("Malformed native oracle result")
    initializer = ",\n".join("{" + ",".join(f"{n}U" for n in expected[i:i + 32]) + "}"
                                for i in range(0, 256, 32))
    checker_source = output / "imported-checker.i"
    checker_source.write_bytes(prefix + DISPATCH.encode() + (f"\nstatic const unsigned int expected[8][32] = {{\n{initializer}\n}};\n" + '''
int main(void) {
  unsigned int k, j, out[32];
  for (k = 0; k < 8; k++) {
    exercise_case(k, out);
    for (j = 0; j < 32; j++)
      if (out[j] != expected[k][j]) return k + 1;
  }
  return 0;
}
''').encode())
    checker_binary = output / "native-checker"
    subprocess.run([compiler] + flags + [str(checker_source), "-o", str(checker_binary)],
                   cwd=unit["directory"], capture_output=True, check=True, timeout=None)
    if subprocess.run([str(checker_binary)], timeout=None).returncode != 0:
        raise ValueError("Native checker does not reproduce the oracle")
    repo = args.cerberus.resolve()
    c_parser = repo / "_build/default/backend/driver/main.exe"
    runtime = repo / "_build/install/default"
    adapter = Path(__file__).with_name("preprocessed_input.py").resolve()
    cabs = output / "imported-checker.cabs.json"
    argv = [str(c_parser), f"--runtime={runtime}", "--cabs-json",
            f"--cpp=python3 {adapter}", str(checker_source)]
    parsed = invoke(argv, cabs, output / "parser.stderr", repo)
    result = {"source": SOURCE, "openssh_commit": census["openssh_commit"],
              "harness_generator_sha256": sha(__file__),
              "source_sha256": unit["source_sha256"], "preprocessed_sha256": sha(original),
              "unchanged_prefix_bytes": len(prefix), "test_cases": CASES,
              "checked_array_elements": 256, "native_compile_arguments": compile_argv,
              "native_oracle_sha256": sha(oracle_binary), "native_checker_sha256": sha(checker_binary),
              "native_array_output_sha256": sha(output / "native-arrays.txt"),
              "checker_source_sha256": sha(checker_source), "parser": parsed,
              "parser_binary_sha256": sha(c_parser), "lean_executed": False, "passed": False,
              "scope": "Eight finite arithmetic-helper regressions from one unchanged complete C unit",
              "whole_x25519_tested": False, "preservation_theorem": False}
    if parsed["exit_code"] != 0:
        result["status"] = "parser_rejected"
    elif args.prepare_only:
        result["status"] = "prepared_not_run_in_lean"
    else:
        lean = repo / "lean_frontend/.lake/build/bin/cerberus-lean"
        argv = [str(repo / "scripts/capped"), str(lean), "--batch", "--runtime", str(runtime), str(cabs)]
        execution = invoke(argv, output / "lean.stdout", output / "lean.stderr", repo, args.timeout or None)
        result.update(lean_executed=True, lean=execution, lean_binary_sha256=sha(lean))
        text = (output / "lean.stdout").read_text(errors="replace").strip()
        # Demand the entire single successful observation; an empty result,
        # fuel exhaustion, extra trace, UB, panic or timeout can never pass.
        result["observation"] = text
        result["passed"] = execution["exit_code"] == 0 and text == (
            'Defined {value: "Specified(0)", stdout: "", stderr: "", blocked: "false"}')
        result["status"] = "passed" if result["passed"] else "lean_did_not_match"
    (output / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"status": result["status"], "report": str(output / "result.json")}))
    return 0 if result["passed"] or (args.prepare_only and parsed["exit_code"] == 0) else 1


if __name__ == "__main__":
    raise SystemExit(main())
