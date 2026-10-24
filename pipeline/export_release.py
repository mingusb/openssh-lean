#!/usr/bin/env python3
"""Build and export configured OpenSSH targets or census units without an agent loop.

Each stage has a durable log and timing record. A failed gate stops the run;
an export is a checked Core data artifact, not behavioral equivalence.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = Path(__file__).resolve().parents[1] / "local/runtime"
sys.path.insert(0, str(ROOT / "work"))
from run_pointer_check_plan import check_build
from export_linked_core import delegated_scope


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    temporary.replace(path)


def run_stage(name, argv, folder, state):
    started = time.monotonic()
    row = {"name": name, "argv": [str(arg) for arg in argv],
           "started_utc": datetime.now(timezone.utc).isoformat(),
           "log": str(folder / (name + ".log")), "terminal": False}
    state["stages"].append(row)
    state["active_stage"] = name
    save(folder / "result.json", state)
    print(json.dumps({"stage": name, "status": "running"}), flush=True)
    with Path(row["log"]).open("w", encoding="utf-8") as log:
        process = subprocess.Popen(row["argv"], cwd=ROOT,
                                   stdout=log, stderr=subprocess.STDOUT)
        code = process.wait()
    row.update(terminal=True, exit_code=code,
               seconds=round(time.monotonic() - started, 3),
               finished_utc=datetime.now(timezone.utc).isoformat())
    save(folder / "result.json", state)
    print(json.dumps({"stage": name, "status": "passed" if code == 0 else "failed",
                      "seconds": row["seconds"], "log": row["log"]}), flush=True)
    if code != 0:
        raise RuntimeError(f"{name} failed; see {row['log']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--jobs", type=int, default=6)
    diagnostic = parser.add_mutually_exclusive_group()
    diagnostic.add_argument("--diagnostic-target", default=None,
                            help="Export one configured native link for profiling")
    diagnostic.add_argument("--model-targets", action="store_true",
                            help="Export Core model data for all configured OpenSSH tools")
    diagnostic.add_argument("--model-target", default=None,
                            help="Export one configured OpenSSH model tool")
    diagnostic.add_argument("--diagnostic-unit", default=None,
                            help="Export one bound census unit for focused validation")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_-]{4,64}", args.run_id) or args.jobs < 1:
        raise ValueError("Use a safe run ID and a positive parallel job count")
    if not delegated_scope():
        os.execvp("systemd-run", ["systemd-run", "--user", "--scope",
                  sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]])
    model_data = args.model_targets or args.model_target is not None
    scope = ("all configured OpenSSH model tools" if args.model_targets else
             "one configured OpenSSH model tool" if args.model_target else
             "one configured native target diagnostic" if args.diagnostic_target else
             "one pinned OpenSSH census unit diagnostic" if args.diagnostic_unit else
             "all configured pinned OpenSSH census source units")
    names = (["run", "host", "ssh-binding", "inventory", "bindings", "core"]
             if args.diagnostic_target or model_data else
             ["run", "host", "ssh-binding", "inventory", "unit-bindings",
              "unit-core"] if args.diagnostic_unit else
             ["run", "host", "ssh-binding", "inventory", "unit-bindings",
              "unit-core", "census-coverage"])
    output = {name: RUNTIME / f"release-{name}-{args.run_id}" for name in names}
    resume = None
    if model_data and output["run"].exists():
        prior = json.loads((output["run"] / "result.json").read_bytes())
        core_path = output["core"] / "result.json"
        if prior.get("terminal") and prior.get("passed") and core_path.is_file():
            current_build = RUNTIME / "logs/whole-table-build.json"
            build_sha = sha(current_build)
            check_build(ROOT, RUNTIME, build_sha)
            core = json.loads(core_path.read_bytes())
            inventory_path = output["inventory"] / "manifest.json"
            inventory = json.loads(inventory_path.read_bytes()) if inventory_path.is_file() else {}
            configured = inventory.get("target_count") if args.model_targets else 1
            if (prior.get("scope") == scope and
                    prior.get("build_receipt_sha256") == build_sha and
                    core.get("terminal") and core.get("passed") and
                    core.get("artifact_format") == "core-data" and
                    configured and core.get("target_count") == configured and
                    len(core.get("targets", [])) == configured and
                    all(row.get("passed") and
                        (args.model_target is None or row.get("target") == args.model_target) and
                        Path(row["output"]).is_file() and
                        sha(row["output"]) == row["output_sha256"]
                        for row in core["targets"])):
                print(json.dumps({"terminal": True, "passed": True,
                                  "reused": True,
                                  "receipt": str(output["run"] / "result.json")}),
                      flush=True)
                return 0
        completed = {row["name"] for row in prior.get("stages", [])
                     if row.get("terminal") and row.get("exit_code") == 0}
        required = {"build", "ssh_inputs", "ssh_binding", "target_inventory"}
        current_build = RUNTIME / "logs/whole-table-build.json"
        build_sha = sha(current_build)
        check_build(ROOT, RUNTIME, build_sha)
        if (prior.get("scope") == scope and
                prior.get("build_receipt_sha256") == build_sha and
                prior.get("outputs") == {name: str(path) for name, path in output.items()} and
                required <= completed and
                all(output[name].exists() for name in
                    ("host", "ssh-binding", "inventory")) and
                not output["bindings"].exists() and
                not output["core"].exists()):
            resume = prior
        else:
            raise FileExistsError("Prior model export cannot resume from verified stages")
    if resume is None and any(path.exists() or path.is_symlink() for path in output.values()):
        raise FileExistsError("One or more run outputs already exist")
    folder = output["run"]
    if resume is None:
        folder.mkdir()
    started = time.monotonic()
    state = resume if resume is not None else {
        "schema_version": 1, "terminal": False, "passed": False,
             "scope": scope,
             "started_utc": datetime.now(timezone.utc).isoformat(),
             "active_stage": None, "stages": [],
             "outputs": {name: str(path) for name, path in output.items()},
             "behavioral_equivalence_proved": False}
    if resume is not None:
        state["terminal"] = False
        state["passed"] = False
        state.pop("error", None)
    save(folder / "result.json", state)
    try:
        if resume is None:
            current = RUNTIME / "logs/whole-table-build.json"
            check_build(ROOT, RUNTIME, sha(current))
            state["stages"].append({"name": "build", "terminal": True,
                                    "exit_code": 0, "reused_verified_receipt": True})
            save(folder / "result.json", state)
        build_receipt = RUNTIME / "logs/whole-table-build.json"
        build_sha = sha(build_receipt)
        check_build(ROOT, RUNTIME, build_sha)
        state["build_receipt_sha256"] = build_sha
        save(folder / "result.json", state)
        if resume is None:
            run_stage("ssh_inputs", [sys.executable,
                str(ROOT / "outputs/openssh-lean/scripts/check_host_dispatch.py"),
                "--workspace", str(ROOT), "--output", str(output["host"]),
                "--build-receipt-sha256", build_sha, "--fuel", "10000",
                "--ssh-inputs-only"], folder, state)
        host_receipt = output["host"] / "result.json"
        host = json.loads(host_receipt.read_bytes())
        if not host.get("passed") or host.get("ssh_startup", {}).get("status") != "inputs-prepared":
            raise RuntimeError("SSH input preparation did not produce checked inputs")
        if resume is None:
            run_stage("ssh_binding", [sys.executable,
                str(ROOT / "work/linked_source_binding.py"), "--receipt",
                str(host_receipt), "--output", str(output["ssh-binding"])],
                folder, state)
            run_stage("target_inventory", [sys.executable,
                str(ROOT / "work/export_target_inventory.py"), "--output",
                str(output["inventory"])], folder, state)
        if args.diagnostic_target or model_data:
            shared = json.loads(output["ssh-binding"].read_bytes())
            imports_path = RUNTIME / "import-fork/import-report.json"
            imports = json.loads(imports_path.read_bytes()) if imports_path.is_file() else {}
            if not (imports.get("openssh_commit") == shared["openssh_commit"] and
                    imports.get("census_sha256") == shared["census_sha256"] and
                    imports.get("parser_binary_sha256") == sha(shared["parser"]["path"]) and
                    imports.get("cpp_adapter_sha256") == sha(shared["cpp_adapter"]["path"])):
                run_stage("cabs_refresh", [sys.executable,
                    str(ROOT / "work/run_import_sweep.py"), "--parser-only"], folder, state)
            run_stage("target_bindings", [sys.executable,
                str(ROOT / "work/bind_export_targets.py"), "--manifest",
                str(output["inventory"] / "manifest.json"),
                "--shared-libc-binding", str(output["ssh-binding"]),
                "--output", str(output["bindings"])], folder, state)
            core_command = [sys.executable,
                str(ROOT / "work/export_all_target_core.py"), "--bindings",
                str(output["bindings"] / "bindings.json"), "--output-dir",
                str(output["core"])]
            if model_data:
                core_command.extend(["--format", "core-data", "--jobs",
                                     str(args.jobs)])
                if args.model_target is not None:
                    core_command.extend(["--target", args.model_target])
            else:
                core_command.extend(["--target", args.diagnostic_target,
                                     "--jobs", "1"])
            run_stage("core_export", core_command, folder, state)
            summary = json.loads((output["core"] / "result.json").read_bytes())
            expected = (json.loads((output["inventory"] / "manifest.json").read_bytes())
                        ["target_count"] if args.model_targets else 1)
            if (not summary.get("passed") or
                    summary.get("passed_count") != expected or
                    summary.get("artifact_format") !=
                    ("core-data" if model_data else "proof")):
                raise RuntimeError("Configured target Core export failed")
            state["passed"] = True
            return 0
        run_stage("unit_bindings", [sys.executable,
            str(ROOT / "work/bind_census_units.py"), "--manifest",
            str(output["inventory"] / "manifest.json"),
            "--shared-libc-binding", str(output["ssh-binding"]),
            "--output", str(output["unit-bindings"])], folder, state)
        unit_export = [sys.executable,
            str(ROOT / "work/export_all_target_core.py"), "--bindings",
            str(output["unit-bindings"] / "bindings.json"), "--output-dir",
            str(output["unit-core"]), "--jobs",
            "1" if args.diagnostic_unit else str(args.jobs)]
        if args.diagnostic_unit:
            unit_export.extend(["--target", args.diagnostic_unit])
        run_stage("unit_core_export", unit_export, folder, state)
        if args.diagnostic_unit:
            summary = json.loads((output["unit-core"] / "result.json").read_bytes())
            if (not summary.get("passed") or summary.get("passed_count") != 1 or
                    summary["targets"][0]["target"] != args.diagnostic_unit):
                raise RuntimeError("Census unit diagnostic Core export failed")
            state["passed"] = True
            return 0
        run_stage("census_coverage", [sys.executable,
            str(ROOT / "work/combine_source_exports.py"), "--manifest",
            str(output["inventory"] / "manifest.json"), "--source-exports",
            str(output["unit-core"] / "result.json"), "--output",
            str(output["census-coverage"])], folder, state)
        coverage = json.loads(output["census-coverage"].read_bytes())
        if (not coverage.get("complete") or
                coverage.get("census_unit_count") != 240):
            raise RuntimeError("Census coverage does not contain all 240 units")
        state["passed"] = True
    except BaseException as error:
        state["error"] = str(error)
    finally:
        state["terminal"] = True
        state["active_stage"] = None
        state["total_seconds"] = round(time.monotonic() - started, 3)
        state["finished_utc"] = datetime.now(timezone.utc).isoformat()
        save(folder / "result.json", state)
        print(json.dumps({"terminal": True, "passed": state["passed"],
                          "receipt": str(folder / "result.json"),
                          "error": state.get("error")}), flush=True)
    return 0 if state["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
