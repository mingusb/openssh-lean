#!/usr/bin/env python3
"""Inventory every configured pinned OpenSSH executable's native TU link closure."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = Path(__file__).resolve().parents[1] / "local/runtime"
REFERENCE = ROOT / "work/reference-source"
PIN = "a8c72b842423f0774f542d3c2197247c3dd28d74"
LOCAL_ARCHIVES = {
    (REFERENCE / "libssh.a").resolve(),
    (REFERENCE / "libssh-pic.a").resolve(),
    (REFERENCE / "openbsd-compat/libopenbsd-compat.a").resolve(),
}
sys.path.insert(0, str(ROOT / "work"))
import build_guard
from run_pointer_check_plan import check_build


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(argv):
    return subprocess.run(argv, cwd=REFERENCE, capture_output=True,
                          text=True, check=True)


def configured_targets():
    rule = "codex-print-targets:\n\t@printf '%s\\n' '$(TARGETS)'"
    names = run(["make", "-s", "--no-print-directory", "--eval", rule,
                 "codex-print-targets"]).stdout.split()
    require(names and len(names) == len(set(names)), "Empty or duplicate TARGETS")
    require(all(re.fullmatch(r"[A-Za-z0-9_.+-]+", name) for name in names),
            "Unsafe configured target name")
    return names


def link_command(target):
    plan = run(["make", "-B", "-n", "--no-print-directory", target]).stdout
    candidates = []
    for line in plan.splitlines():
        try:
            argv = shlex.split(line)
        except ValueError:
            continue
        if "-c" in argv or "-o" not in argv:
            continue
        index = argv.index("-o")
        if index + 1 < len(argv) and argv[index + 1] == target:
            candidates.append(argv)
    require(len(candidates) == 1,
            f"{target}: expected one final link command, saw {len(candidates)}")
    return plan, candidates[0]


def object_index(units):
    result = {}
    for unit in units:
        argv = unit["arguments"]
        name = argv[argv.index("-o") + 1] if "-o" in argv else Path(unit["file"]).with_suffix(".o").name
        obj = (Path(unit["directory"]) / name).resolve()
        require(obj not in result, f"Multiple census units map to {obj}")
        result[obj] = unit
    return result


def linked_objects(command, map_text):
    direct = [(REFERENCE / item).resolve() for item in command
              if item.endswith((".o", ".lo")) and not item.startswith("-")]
    archive_members = []
    for line in map_text.splitlines():
        if line == "Merging object attributes":
            break
        match = re.match(r"^(\S+\.a)\(([^()]+\.(?:o|lo))\)", line)
        if match is None:
            continue
        library = (REFERENCE / match.group(1)).resolve()
        if library in LOCAL_ARCHIVES:
            archive_members.append((library.parent / match.group(2)).resolve())
        elif library.is_relative_to(REFERENCE):
            raise RuntimeError(f"Unaccounted local archive: {library}")
    ordered = direct + archive_members
    require(len(ordered) == len(set(ordered)),
            "Duplicate direct or archive-selected object in link closure")
    return ordered


def validate_census(census_path):
    census = json.loads(census_path.read_bytes())
    require(census["openssh_commit"] == PIN and
            Path(census["source_root"]) == REFERENCE,
            "Census does not describe the pinned Linux checkout")
    require(sha(REFERENCE / "Makefile") == census["makefile_sha256"] and
            sha(REFERENCE / "config.h") == census["configuration_sha256"],
            "Configured files differ from census")
    units = census["translation_units"]
    require(len(units) == len({row["source"] for row in units}),
            "Duplicate source in census")
    for unit in units:
        pre = unit["preprocessing"]
        require(sha(unit["file"]) == unit["source_sha256"] and
                pre["exit_code"] == 0 and sha(pre["path"]) == pre["sha256"],
                f"Source/preprocessing changed: {unit['source']}")
    return census, object_index(units)


def target_record(target, folder, index):
    started = time.monotonic()
    plan, original = link_command(target)
    plan_seconds = round(time.monotonic() - started, 3)
    target_dir = folder / target
    target_dir.mkdir()
    (target_dir / "build-plan.txt").write_text(plan, encoding="utf-8")
    map_path = target_dir / "link.map"
    linked_path = target_dir / "native-linked"
    command = list(original)
    command[command.index("-o") + 1] = str(linked_path)
    command.append("-Wl,-Map=" + str(map_path))
    link_started = time.monotonic()
    completed = run(command)
    link_seconds = round(time.monotonic() - link_started, 3)
    (target_dir / "link.stdout").write_text(completed.stdout, encoding="utf-8")
    (target_dir / "link.stderr").write_text(completed.stderr, encoding="utf-8")
    ordered = linked_objects(original, map_path.read_text(encoding="utf-8"))
    missing = [str(obj) for obj in ordered if obj not in index]
    require(not missing, f"{target}: linked objects absent from census: {missing}")
    sources = []
    for obj in ordered:
        unit = index[obj]
        pre = unit["preprocessing"]
        require(sha(unit["file"]) == unit["source_sha256"] and
                sha(pre["path"]) == pre["sha256"],
                f"{target}: linked input changed: {obj}")
        sources.append({
            "source": unit["source"], "object_path": str(obj),
            "object_sha256": sha(obj), "original_path": unit["file"],
            "original_sha256": unit["source_sha256"],
            "preprocessed_path": pre["path"],
            "preprocessed_sha256": pre["sha256"],
        })
    native = REFERENCE / target
    require(native.is_file(), f"{target}: native binary missing")
    externals = run(["nm", "-D", "--undefined-only", "--format=posix",
                     str(linked_path)]).stdout.splitlines()
    timing = {"plan_seconds": plan_seconds, "native_relink_seconds": link_seconds,
              "total_seconds": round(time.monotonic() - started, 3)}
    return {
        "target": target,
        "native_path": str(native), "native_sha256": sha(native),
        "relinked_path": str(linked_path), "relinked_sha256": sha(linked_path),
        "build_plan_path": str(target_dir / "build-plan.txt"),
        "build_plan_sha256": sha(target_dir / "build-plan.txt"),
        "link_arguments": original, "relink_arguments": command,
        "link_map_path": str(map_path), "link_map_sha256": sha(map_path),
        "ordered_sources": [row["source"] for row in sources],
        "linked_unit_count": len(sources), "units": sources,
        "dynamic_undefined_symbols": externals, "timing": timing,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.absolute()
    require(output.parent == RUNTIME and not output.exists() and
            not output.is_symlink(), "Output must be a fresh direct runtime child")
    started = time.monotonic()
    with build_guard.workflow_lock():
        build_guard.verify_tools()
        build_receipt = RUNTIME / "logs/whole-table-build.json"
        check_build(ROOT, RUNTIME, sha(build_receipt))
        census_path = RUNTIME / "c-import/census.json"
        census, index = validate_census(census_path)
        targets = configured_targets()
        preparation_seconds = round(time.monotonic() - started, 3)
        output.mkdir()
        records = []
        for target in targets:
            record = target_record(target, output, index)
            records.append(record)
            print(json.dumps({"target": target,
                              "linked_units": record["linked_unit_count"]}), flush=True)
        seen = set().union(*(set(row["ordered_sources"]) for row in records))
        all_sources = {row["source"] for row in census["translation_units"]}
        report = {
            "schema_version": 1,
            "scope": "configured-pinned-openssh-native-link-closures",
            "openssh_commit": PIN,
            "build_receipt_path": str(build_receipt),
            "build_receipt_sha256": sha(build_receipt),
            "census_path": str(census_path), "census_sha256": sha(census_path),
            "generator_path": str(Path(__file__).resolve()),
            "generator_sha256": sha(__file__),
            "makefile_sha256": sha(REFERENCE / "Makefile"),
            "targets": records, "target_count": len(records),
            "linked_source_union": sorted(seen),
            "linked_source_union_count": len(seen),
            "census_unit_count": len(all_sources),
            "unlinked_census_sources": sorted(all_sources - seen),
            "unlinked_census_count": len(all_sources - seen),
            "timing": {"preparation_seconds": preparation_seconds,
                       "total_seconds": round(time.monotonic() - started, 3)},
            "limitations": [
                "Configured native targets only; inactive platform and optional branches are separate.",
                "Native link closure is source provenance, not Core export or behavior proof.",
                "Dynamic libraries, runtime-loaded providers, and host effects are separate boundaries.",
            ],
        }
        path = output / "manifest.json"
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
        print(json.dumps({"targets": len(records),
                          "linked_source_union": len(seen),
                          "unlinked_census": len(all_sources - seen),
                          "manifest": str(path)}), flush=True)


if __name__ == "__main__":
    main()
