#!/usr/bin/env python3
"""Bind cached Cabs and shared libc inputs to every checked target link closure.

The output proves input identity at export time; it does not prove translation
correctness or behavioral equivalence.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = Path(__file__).resolve().parents[1] / "local/runtime"
SCRIPTS = ROOT / "outputs/openssh-lean/scripts"
sys.path.insert(0, str(ROOT / "work"))
sys.path.insert(0, str(SCRIPTS))
import build_guard
from run_pointer_check_plan import check_build
import ssh_startup_inputs as inputs
from linked_source_binding import cabs_digest, md5


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def checked(path, expected, label):
    require(Path(path).is_file() and sha(path) == expected,
            f"{label} changed: {path}")


def load_inputs(manifest_path, shared_path):
    manifest = json.loads(manifest_path.read_bytes())
    shared = json.loads(shared_path.read_bytes())
    require(manifest["scope"] == "configured-pinned-openssh-native-link-closures" and
            manifest["openssh_commit"] == inputs.PIN and
            manifest["target_count"] == len(manifest["targets"]) and
            shared["scope"] == "configured-ssh-link-input-provenance" and
            shared["input_provenance_verified"] is True and
            shared["receipt_mode"] == "ssh-inputs-only" and
            shared["openssh_commit"] == inputs.PIN,
            "Manifest or shared-libc source binding has the wrong scope")
    checked(manifest["generator_path"], manifest["generator_sha256"],
            "Target-closure generator")
    checked(manifest["census_path"], manifest["census_sha256"], "Census")
    checked(manifest["build_receipt_path"], manifest["build_receipt_sha256"],
            "Build receipt")
    checked(shared["host_receipt_path"], shared["host_receipt_sha256"],
            "Shared-libc host receipt")
    checked(shared["translator"]["path"], shared["translator"]["sha256"],
            "Lean translator")
    checked(shared["parser"]["path"], shared["parser"]["sha256"],
            "C parser")
    for row in shared["frontend_order"]:
        checked(row["cabs_path"], row["cabs_sha256"], "Shared ssh Cabs")
    checked(shared["libc"]["core"]["path"], shared["libc"]["core"]["sha256"],
            "Shared libc Core")
    for row in shared["libc"]["metadata_order"]:
        checked(row["source_path"], row["source_sha256"], "Libc source")
        checked(row["cabs_path"], row["cabs_sha256"], "Libc metadata")
    for row in shared["runtime"].values():
        checked(row["path"], row["sha256"], "Runtime")
    require(manifest["build_receipt_sha256"] == shared["build_receipt_sha256"] and
            manifest["census_sha256"] == shared["census_sha256"],
            "Target closure and shared libc use different build/census inputs")
    check_build(ROOT, RUNTIME, manifest["build_receipt_sha256"])
    return manifest, shared


def checked_imports(shared):
    path = RUNTIME / "import-fork/import-report.json"
    report = json.loads(path.read_bytes())
    parser = shared["parser"]["path"]
    cpp = shared["cpp_adapter"]["path"]
    require(report["openssh_commit"] == inputs.PIN and
            report["census_sha256"] == shared["census_sha256"] and
            report["parser_binary_sha256"] == sha(parser) and
            report["cpp_adapter_sha256"] == sha(cpp),
            "Cached Cabs producer differs from target inputs")
    rows = {row["source"]: row for row in report["units"]}
    require(len(rows) == len(report["units"]), "Duplicate imported source")
    return path, rows


def bind_one(target, manifest_path, manifest, shared_path, shared, imports):
    target_name = target["target"]
    checked(target["native_path"], target["native_sha256"], "Native target")
    checked(target["link_map_path"], target["link_map_sha256"], "Link map")
    checked(target["build_plan_path"], target["build_plan_sha256"], "Build plan")
    checked(target["relinked_path"], target["relinked_sha256"], "Relinked target")
    require(target["linked_unit_count"] == len(target["units"]) ==
            len(target["ordered_sources"]) and
            target["ordered_sources"] == [row["source"] for row in target["units"]] and
            len(set(target["ordered_sources"])) == len(target["ordered_sources"]),
            f"{target_name}: incomplete or duplicate ordered source closure")
    frontend = []
    parser = shared["parser"]["path"]
    installed = RUNTIME / "cerberus-lean/_build/install/default"
    cpp = shared["cpp_adapter"]["path"]
    for unit in target["units"]:
        source = unit["source"]
        imported = imports[source]
        pre = unit["preprocessed_path"]
        checked(unit["original_path"], unit["original_sha256"], "Target source")
        checked(pre, unit["preprocessed_sha256"], "Preprocessed TU")
        checked(unit["object_path"], unit["object_sha256"], "Linked object")
        require(imported["source_sha256"] == unit["original_sha256"] and
                imported["preprocessed_sha256"] == unit["preprocessed_sha256"],
                f"{target_name}: cached Cabs input identity differs: {source}")
        row = imported["parser"]
        cab = row["stdout_path"]
        checked(cab, row["stdout_sha256"], "Cabs")
        require(row["exit_code"] == 0 and not row["timed_out"] and
                row["arguments"] == inputs.cabs_arguments(
                    Path(parser), installed, Path(cpp), Path(pre)) and
                Path(cab).resolve().is_relative_to(RUNTIME / "import-fork/units") and
                cabs_digest(cab) == md5(pre),
                f"{target_name}: Cabs did not come from current preprocessed TU: {source}")
        frontend.append({
            "source": source,
            "original_path": unit["original_path"],
            "original_sha256": unit["original_sha256"],
            "preprocessed_path": pre,
            "preprocessed_sha256": unit["preprocessed_sha256"],
            "preprocessed_digest_md5": md5(pre),
            "cabs_path": cab,
            "cabs_sha256": row["stdout_sha256"],
            "cabs_digest_md5": cabs_digest(cab),
            "parser_argv": row["arguments"],
        })
    prior = shared["lean_argv"]
    old_count = len(shared["frontend_order"])
    require(old_count > 0 and prior[-old_count:] ==
            [row["cabs_path"] for row in shared["frontend_order"]],
            "Shared binding does not end in its ordered Cabs inputs")
    argv = prior[:-old_count] + [row["cabs_path"] for row in frontend]
    return {
        "schema_version": 2,
        "scope": "configured-openssh-target-link-input-provenance",
        "target": target_name,
        "receipt_mode": "target-inputs-only",
        "input_provenance_verified": True,
        "linked_core_certified": False,
        "linked_execution_verified": False,
        "behavioral_equivalence_proved": False,
        "lean_argv_executed": False,
        "openssh_commit": inputs.PIN,
        "target_manifest_path": str(manifest_path),
        "target_manifest_sha256": sha(manifest_path),
        "target_link_map_path": target["link_map_path"],
        "target_link_map_sha256": target["link_map_sha256"],
        "native_target": {"path": target["native_path"],
                          "sha256": target["native_sha256"]},
        "shared_libc_binding_path": str(shared_path),
        "shared_libc_binding_sha256": sha(shared_path),
        "census_path": manifest["census_path"],
        "census_sha256": manifest["census_sha256"],
        "build_receipt_path": shared["build_receipt_path"],
        "build_receipt_sha256": shared["build_receipt_sha256"],
        "binding_generator_path": str(Path(__file__).resolve()),
        "binding_generator_sha256": sha(__file__),
        "cpp_adapter": shared["cpp_adapter"],
        "parser": shared["parser"],
        "translator": shared["translator"],
        "frontend_order": frontend,
        "core_link_order": list(range(len(frontend) - 1, -1, -1)) + ["libc"],
        "libc": shared["libc"],
        "runtime": shared["runtime"],
        "semantic_switches": shared["semantic_switches"],
        "host_abi": shared["host_abi"],
        "fuel": shared["fuel"],
        "address_space_top": shared["address_space_top"],
        "lean_argv": argv,
        "limitations": [
            "Binding verifies bytes and producers, not C-to-Core equivalence.",
            "The linked Core export has not run when this binding is emitted.",
            "Target scope is the configured native link, not inactive branches or host effects.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--shared-libc-binding", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.absolute()
    require(output.parent == RUNTIME and not output.exists() and
            not output.is_symlink(), "Output must be a fresh direct runtime child")
    started = time.monotonic()
    with build_guard.workflow_lock():
        build_guard.verify_tools()
        manifest_path = args.manifest.resolve(strict=True)
        shared_path = args.shared_libc_binding.resolve(strict=True)
        manifest, shared = load_inputs(manifest_path, shared_path)
        imports_path, imports = checked_imports(shared)
        input_validation_seconds = round(time.monotonic() - started, 3)
        timings = {}
        bindings = []
        for target in manifest["targets"]:
            target_started = time.monotonic()
            bindings.append(bind_one(target, manifest_path, manifest, shared_path,
                                     shared, imports))
            timings[target["target"]] = round(time.monotonic() - target_started, 3)
        require(len(bindings) == len({row["target"] for row in bindings}),
                "Duplicate configured target")
        output.mkdir()
        summary = []
        for binding in bindings:
            path = output / (binding["target"] + ".json")
            path.write_text(json.dumps(binding, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8")
            summary.append({"target": binding["target"],
                            "linked_units": len(binding["frontend_order"]),
                            "path": str(path), "sha256": sha(path)})
        receipt = {
            "schema_version": 1, "scope": "all-configured-target-input-bindings",
            "manifest_path": str(manifest_path), "manifest_sha256": sha(manifest_path),
            "shared_libc_binding_path": str(shared_path),
            "shared_libc_binding_sha256": sha(shared_path),
            "import_report_path": str(imports_path),
            "import_report_sha256": sha(imports_path),
            "targets": summary,
            "timing": {"input_validation_seconds": input_validation_seconds,
                       "target_binding_seconds": timings,
                       "total_seconds": round(time.monotonic() - started, 3)},
        }
        receipt_path = output / "bindings.json"
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                                encoding="utf-8")
        print(json.dumps({"targets": len(summary), "bindings": str(receipt_path)}))


if __name__ == "__main__":
    main()
