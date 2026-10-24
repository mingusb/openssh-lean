#!/usr/bin/env python3
"""Capture configured OpenSSH C inputs and survey their syntax.

This is an input/provenance collector, not a translator or equivalence checker.
Runs on Linux in the configured reference build directory. Build-plan commands
are parsed into argv; shell text from the plan is never executed.
"""
from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess

PIN = "a8c72b842423f0774f542d3c2197247c3dd28d74"


def sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def parse_plan(plan: str, root: Path) -> list[dict]:
    directory = root
    rows = {}
    for line in plan.splitlines():
        entering = re.fullmatch(r"make\[\d+\]: Entering directory '(.+)'", line)
        leaving = re.fullmatch(r"make\[\d+\]: Leaving directory '(.+)'", line)
        if entering:
            directory = Path(entering[1]).resolve()
            directory.relative_to(root)
            continue
        if leaving:
            directory = Path(leaving[1]).resolve().parent
            continue
        if not re.match(r"^(?:\S*/)?(?:cc|gcc|clang)(?:-[0-9]+)? ", line):
            continue
        argv = shlex.split(line)
        if "-c" not in argv:
            continue
        sources = [a for a in argv[1:] if a.endswith(".c")]
        if len(sources) != 1:
            raise ValueError(f"Expected one C input: {line}")
        source = (directory / sources[0]).resolve()
        relative = str(source.relative_to(root))
        if relative in rows and rows[relative]["arguments"] != argv:
            raise ValueError(f"Multiple configurations for {relative}")
        rows[relative] = {
            "file": str(source), "source": relative,
            "directory": str(directory), "arguments": argv,
        }
    if not rows or "sftp-server.c" not in rows or "ssh.c" not in rows:
        raise ValueError("Build plan does not contain the expected whole-program targets")
    return sorted(rows.values(), key=lambda r: r["source"])


def preprocess_args(row: dict) -> list[str]:
    argv = row["arguments"]
    result = [argv[0]]
    i = 1
    while i < len(argv):
        if argv[i] == "-o":
            i += 2
        elif argv[i] == "-c":
            i += 1
        else:
            result.append(argv[i])
            i += 1
    return result + ["-E"]


def survey(tree: dict) -> dict:
    kinds = Counter()
    definitions = []
    direct_calls = Counter()
    stack = [tree]
    while stack:
        node = stack.pop()
        kind = node.get("kind", "")
        if kind:
            kinds[kind] += 1
        inner = node.get("inner", [])
        if kind == "FunctionDecl" and any(n.get("kind") == "CompoundStmt" for n in inner):
            definitions.append({"name": node.get("name"), "location": node.get("loc", {}),
                                "type": node.get("type", {}).get("qualType")})
        if kind == "CallExpr" and inner:
            expr = inner[0]
            while expr.get("kind") in {"ImplicitCastExpr", "ParenExpr"} and expr.get("inner"):
                expr = expr["inner"][0]
            target = expr.get("referencedDecl", {})
            if target.get("kind") == "FunctionDecl":
                direct_calls[target.get("name", "<unnamed>")] += 1
            else:
                direct_calls["<indirect>"] += 1
        stack.extend(inner)
    return {"node_kinds": dict(sorted(kinds.items())),
            "function_definitions_including_headers": definitions,
            "call_sites_by_direct_callee": dict(sorted(direct_calls.items()))}


def capture(row: dict, output: Path, clang: str) -> dict:
    relative = Path(row["source"])
    target = (output / "units" / relative).with_suffix(".i")
    target.parent.mkdir(parents=True, exist_ok=True)
    log = target.with_suffix(".preprocess.stderr")
    argv = preprocess_args(row)
    with target.open("wb") as stdout, log.open("wb") as stderr:
        result = subprocess.run(argv, cwd=row["directory"], stdout=stdout, stderr=stderr,
                                timeout=120, check=False)
    record = dict(row, source_sha256=sha(Path(row["file"])),
                  preprocessing={"arguments": argv, "exit_code": result.returncode,
                                 "stderr_sha256": sha(log)})
    if result.returncode:
        record["status"] = "preprocessing_failed"
        return record
    record["preprocessing"].update({"path": str(target), "sha256": sha(target),
                                     "bytes": target.stat().st_size})
    ast = target.with_suffix(".ast.json")
    astlog = target.with_suffix(".ast.stderr")
    # Clang is used only for a syntax survey of GCC's already-preprocessed text.
    # It is not the reference compiler or a semantics-preserving translation.
    clang_argv = [clang, "-std=gnu23", "-x", "cpp-output", "-fsyntax-only", "-Xclang", "-ast-dump=json",
                  str(target)]
    with ast.open("wb") as stdout, astlog.open("wb") as stderr:
        result = subprocess.run(clang_argv, cwd=row["directory"], stdout=stdout,
                                stderr=stderr, timeout=120, check=False)
    record["syntax_survey"] = {"arguments": clang_argv, "exit_code": result.returncode,
                               "ast_sha256": sha(ast), "stderr_sha256": sha(astlog),
                               "diagnostic_excerpt": astlog.read_text(errors="replace")[:2000]}
    if result.returncode == 0:
        record["syntax_survey"].update(survey(json.loads(ast.read_text())))
        record["status"] = "syntax_surveyed"
    else:
        record["status"] = "syntax_survey_failed"
    # An additional advisory survey uses Clang's own header branches. This is
    # intentionally separate from the exact GCC input, and is NEVER supplied
    # as a replacement to the semantic importer.
    source_ast = target.with_suffix(".clang-source.ast.json")
    source_log = target.with_suffix(".clang-source.stderr")
    source_argv = [clang] + preprocess_args(row)[1:-1] + [
        "-std=gnu23", "-fsyntax-only", "-Xclang", "-ast-dump=json"]
    with source_ast.open("wb") as stdout, source_log.open("wb") as stderr:
        source_result = subprocess.run(source_argv, cwd=row["directory"], stdout=stdout,
                                       stderr=stderr, timeout=120, check=False)
    record["advisory_clang_source_survey"] = {
        "arguments": source_argv, "exit_code": source_result.returncode,
        "ast_sha256": sha(source_ast), "stderr_sha256": sha(source_log),
        "diagnostic_excerpt": source_log.read_text(errors="replace")[:1000],
        "matches_reference_preprocessing": False,
    }
    if source_result.returncode == 0:
        record["advisory_clang_source_survey"].update(survey(json.loads(source_ast.read_text())))
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clang", required=True)
    parser.add_argument("--jobs", type=int, default=4, choices=range(1, 9))
    args = parser.parse_args()
    root = args.source.resolve()
    inventory = json.loads(args.inventory.read_text())
    pin = inventory.get("upstream_commit", inventory.get("commit"))
    # The inventory pin is embedded in its upstream object in current schema.
    if pin is None:
        pin = inventory.get("upstream", {}).get("commit")
    if pin != PIN:
        raise ValueError(f"Wrong source inventory pin: {pin!r}")
    pinned = {row["path"]: row for row in inventory["files"]}
    verified = []
    for path, record in pinned.items():
        if Path(path).suffix in {".c", ".h"}:
            if sha(root / path) != record["sha256"]:
                raise ValueError(f"Pinned source bytes changed: {path}")
            verified.append(path)
    rows = parse_plan(args.plan.read_text(), root)
    for row in rows:
        if row["source"] not in pinned:
            raise ValueError(f"Uninventoried build input: {row['source']}")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "compile_commands.json", rows)
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(lambda row: capture(row, output, args.clang), rows))
    compiled = {row["source"] for row in rows}
    report = {
        "schema_version": 1, "openssh_commit": PIN,
        "profile": "Linux x86_64; --without-openssl --without-zlib",
        "generator_sha256": sha(Path(__file__)), "plan_sha256": sha(args.plan),
        "inventory_sha256": sha(args.inventory), "source_root": str(root),
        "verified_unchanged_source_headers": len(verified),
        "configuration_sha256": sha(root / "config.h"),
        "config_status_sha256": sha(root / "config.status"),
        "makefile_sha256": sha(root / "Makefile"),
        "compiler_version": subprocess.check_output([rows[0]["arguments"][0], "--version"], text=True),
        "survey_frontend_version": subprocess.check_output([args.clang, "--version"], text=True),
        "translation_units": results,
        "counts": dict(Counter(row["status"] for row in results)),
        "c_sources_not_in_this_build_plan": sorted(path for path in pinned
                                                    if path.endswith(".c") and path not in compiled),
        "limits": ["The build plan is make all for one configuration, not all platforms or regress targets.",
                   "Inactive conditional source is not represented by the preprocessed files.",
                   "The syntax survey uses Clang on GCC-preprocessed text and is not semantic execution.",
                   "Compiler lowering, external-library implementations, and system effects are not modeled."],
        "lean_import_performed": False, "behavioral_equivalence_proved": False,
    }
    write_json(output / "census.json", report)
    print(json.dumps({"translation_units": len(results), "counts": report["counts"],
                      "report": str(output / "census.json")}))
    return 1 if report["counts"].get("preprocessing_failed") else 0


if __name__ == "__main__":
    raise SystemExit(main())
