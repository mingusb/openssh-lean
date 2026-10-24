#!/usr/bin/env python3
"""Derive the pinned ssh client's actual object closure from a native link map."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import shlex
import subprocess
from exercise_imported_c import sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--census", type=Path, required=True)
    parser.add_argument("--imports", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    census = json.loads(args.census.read_text())
    assert census["openssh_commit"] == "a8c72b842423f0774f542d3c2197247c3dd28d74"
    units = census["translation_units"]
    reference = Path(next(u["directory"] for u in units if u["source"] == "ssh.c"))
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    plan = subprocess.run(["make", "-B", "-n", "ssh"], cwd=reference, capture_output=True, text=True, check=True, timeout=60)
    (output / "build-plan.txt").write_text(plan.stdout)
    candidates = []
    for line in plan.stdout.splitlines():
        if re.match(r"^(?:\S*/)?(?:cc|gcc|clang)(?:-[0-9]+)? ", line):
            argv = shlex.split(line)
            if "-c" not in argv and "-o" in argv and argv[argv.index("-o") + 1] == "ssh":
                candidates.append(argv)
    assert len(candidates) == 1, candidates
    command = candidates[0]
    link_map = output / "ssh.map"
    binary = output / "ssh.reference"
    command[command.index("-o") + 1] = str(binary)
    command.append("-Wl,-Map=" + str(link_map))
    # Execute a parsed argv, never shell text from the build plan. Preserve all
    # configured inputs/options; change only the output and request a link map.
    subprocess.run(command, cwd=reference, capture_output=True, check=True, timeout=60)
    map_text = link_map.read_text()
    selected = {(reference / a).resolve() for a in command if a.endswith(".o")}
    archives = re.findall(r"(?m)^([^\s()]+\.a)\(([^()]+\.o)\)", map_text)
    local_archives = {(reference / "libssh.a").resolve(), (reference / "openbsd-compat/libopenbsd-compat.a").resolve()}
    for archive, member in archives:
        library = (reference / archive).resolve()
        if library in local_archives:
            selected.add((library.parent / member).resolve())
        elif library.is_relative_to(reference):
            raise ValueError(f"Unexpected local archive {library}")
    object_units = {}
    for unit in units:
        argv = unit["arguments"]
        object_name = argv[argv.index("-o") + 1] if "-o" in argv else Path(unit["file"]).with_suffix(".o").name
        obj = (Path(unit["directory"]) / object_name).resolve()
        object_units[obj] = unit
    assert not (selected - object_units.keys()), sorted(str(p) for p in selected - object_units.keys())
    status = {row["source"]: row for row in json.loads(args.imports.read_text())["units"]}
    rows, blockers, constructs = [], Counter(), Counter()
    extension_nodes = {"GCCAsmStmt", "StmtExpr", "GenericSelectionExpr", "VAArgExpr", "AtomicExpr",
                       "IndirectGotoStmt", "AddrLabelExpr", "PredefinedExpr", "TypeOfExprType"}
    for obj in sorted(selected):
        unit = object_units[obj]
        assert sha(unit["file"]) == unit["source_sha256"]
        pp = unit["preprocessing"]
        assert sha(pp["path"]) == pp["sha256"]
        imported = status.get(unit["source"], {})
        diagnostic = imported.get("parser", {}).get("diagnostics", "").splitlines()
        blocker = None
        if imported.get("status", "").startswith("c_parser_") and diagnostic:
            blocker = next((line for line in diagnostic if ": error:" in line), diagnostic[0])
        if blocker:
            blockers[blocker] += 1
        advisory = unit.get("advisory_clang_source_survey", {})
        if advisory.get("exit_code") == 0:
            for kind, count in advisory.get("node_kinds", {}).items():
                if count and (kind.endswith("Attr") or kind in extension_nodes):
                    constructs[kind] += 1
        rows.append({"source": unit["source"], "object_sha256": sha(obj),
                     "source_sha256": unit["source_sha256"], "preprocessed_sha256": pp["sha256"],
                     "status": imported.get("status", "not_attempted"), "first_parser_blocker": blocker})
    externals = subprocess.check_output(["nm", "-D", "--undefined-only", "--format=posix", str(binary)], text=True)
    (output / "dynamic-externals.txt").write_text(externals)
    record = {"openssh_commit": census["openssh_commit"], "executable_priority": "ssh",
              "census_sha256": sha(args.census), "import_report_sha256": sha(args.imports),
              "script_sha256": sha(__file__), "link_arguments": command, "link_map_sha256": sha(link_map),
              "native_reference_sha256": sha(binary), "whole_build_unit_count": len(units),
              "ssh_linked_unit_count": len(rows), "counts": dict(Counter(row["status"] for row in rows)),
              "shared_parser_blockers": [{"diagnostic": key, "units": count} for key, count in blockers.most_common()],
              "advisory_clang_construct_units": dict(constructs.most_common()),
              "dynamic_external_symbols": externals.splitlines(), "units": rows,
              "limitations": ["Native link closure for this pinned build only; not a Lean build or behavior proof.",
                              "A first-error count shows the current shared obstacle, not all remaining obstacles.",
                              "Clang construct counts use the advisory Clang-preprocessed survey, not the exact GCC inputs or a support verdict.",
                              "Runtime-loaded providers and helper executables require additional dependencies."]}
    target = output / "result.json"
    target.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"ssh_linked_units": len(rows), "whole_build_units": len(units),
                      "counts": record["counts"], "blockers": record["shared_parser_blockers"][:5], "report": str(target)}))


if __name__ == "__main__":
    main()
