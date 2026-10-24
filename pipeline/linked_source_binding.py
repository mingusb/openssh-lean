#!/usr/bin/env python3
"""Fail-closed source binding for an existing checked 90-TU ssh host receipt.

This does not prove C preprocessing, C-to-Core translation, or behavior.
It verifies the existing production receipts and all current input bytes,
without running the parser, Lean compiler, or ssh.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = Path(__file__).resolve().parents[1] / "local/runtime"
SCRIPTS = ROOT / "outputs/openssh-lean/scripts"
sys.path.insert(0, str(SCRIPTS))
import ssh_startup_inputs as inputs
sys.path.insert(0, str(ROOT / "work"))
from run_pointer_check_plan import check_build

LIBC_NAMES = inputs.LIBC_TUS
IMPLEMENTATION = "gcc_4.9.0_x86_64-apple-darwin10.8.0.impl"
ADDRESS_SPACE_TOP = 0xFFFFFFFFFFFF


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    return inputs.sha(Path(path))


def md5(path):
    digest = hashlib.md5()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cabs_digest(path):
    """Read the producer's final, top-level digest without loading a huge AST."""
    with Path(path).open("rb") as stream:
        stream.seek(0, 2)
        size = stream.tell()
        stream.seek(max(0, size - 4096))
        tail = stream.read()
    found = re.search(rb'\n  "digest": "([0-9a-f]{32})"\n}\s*\Z', tail)
    require(found is not None, f"Cabs final digest missing or malformed: {path}")
    return found.group(1).decode("ascii")


def indexed_steps(receipt):
    rows = receipt["steps"]
    result = {row["label"]: row for row in rows}
    require(len(rows) == len(result), "Duplicate step labels")
    return result


def checked_artifact(receipt, path, expected):
    path = str(path)
    require(receipt["artifact_hashes_before"].get(path) == expected and
            receipt["artifact_hashes_after"].get(path) == expected,
            f"Receipt artifact identity absent/changed: {path}")
    require(sha(path) == expected, f"Receipt artifact bytes changed: {path}")


def checked_cabs_rows(plan, receipt, census, parser, installed):
    recorded = receipt["ssh_startup"]["cabs_inputs"]
    require(len(plan["units"]) == len(recorded) == 90, "Expected exactly 90 ordered ssh Cabs")
    steps = indexed_steps(receipt)
    by_source = inputs.indexed(census["translation_units"], "source", "census TU")
    output = []
    for index, (unit, cab) in enumerate(zip(plan["units"], recorded, strict=True)):
        source = unit["source"]
        require(cab["source"] == source, f"Cabs/frontend order mismatch at {index}")
        original = Path(by_source[source]["file"])
        pre = Path(unit["preprocessed"])
        path = Path(cab["path"])
        require(original.is_absolute() and pre.is_absolute() and path.is_absolute(),
                f"Relative provenance path at {index}")
        require(sha(original) == unit["source_sha256"] and
                sha(pre) == unit["preprocessed_sha256"],
                f"Source/preprocessed bytes changed at {index}")
        checked_artifact(receipt, path, cab["sha256"])
        expected_argv = inputs.cabs_arguments(parser, installed, plan["cpp_adapter"], pre)
        if cab["producer"] == "verified-current-parser-cache":
            require(unit["cached_cabs"] == str(path),
                    f"Cached Cabs is not currently admitted at {index}")
        else:
            step = steps.get(cab["producer"])
            require(cab["producer"] == f"ssh-cabs-{index:03d}" and step is not None,
                    f"Unrecognized Cabs producer at {index}")
            require(step["argv"] == expected_argv and
                    step["stdout"]["path"] == str(path) and
                    step["stdout"]["sha256"] == cab["sha256"] and
                    step["exit_code"] == 0 and not step["residual_processes"],
                    f"Cabs producer command/result differs at {index}")
        digest = cabs_digest(path)
        pre_md5 = md5(pre)
        require(digest == pre_md5, f"Cabs carried digest differs from translation input at {index}")
        output.append({
            "source": source,
            "original_path": str(original),
            "original_sha256": unit["source_sha256"],
            "preprocessed_path": str(pre),
            "preprocessed_sha256": unit["preprocessed_sha256"],
            "preprocessed_digest_md5": pre_md5,
            "cabs_path": str(path),
            "cabs_sha256": cab["sha256"],
            "cabs_digest_md5": digest,
            "parser_argv": expected_argv,
        })
    return output


def checked_libc_profile(root, runtime, parser, lean, receipt, cabs, receipt_mode):
    profile_row = receipt["ssh_startup"]["libc_profile"]
    profile_path = Path(profile_row["path"])
    preparer = root / "work/cerberus-lean/scripts/prepare_gnu_amd64_libc.py"
    repo = runtime / "cerberus-lean"
    require(sha(profile_path) == profile_row["sha256"], "Libc profile receipt changed")
    require(inputs.profile_is_current(profile_path.parent, repo, preparer),
            "Libc profile is stale, incomplete, or has changed sources")
    profile = json.loads(profile_path.read_bytes())
    installed = repo / "_build/install/default"
    artifact_dir = profile_path.parent
    core_path = artifact_dir / "libc_gnu_amd64.core"
    checked_artifact(receipt, core_path, profile["artifact_sha256"][core_path.name])
    metadata = []
    source_dir = repo / "runtime/libc/src"
    for name in LIBC_NAMES:
        source = source_dir / f"{name}.c"
        path = artifact_dir / f"libc_gnu_amd64_{name}.json"
        digest = cabs_digest(path)
        source_md5 = md5(source)
        require(digest == source_md5, f"Libc metadata Cabs digest mismatch: {name}")
        expected_sha = profile["artifact_sha256"][path.name]
        checked_artifact(receipt, path, expected_sha)
        step = next((item for item in profile["steps"] if item["name"] == f"metadata-{name}"), None)
        require(step is not None and step["output"] == str(path) and
                step["argv"][-2:] == ["--cabs-json", str(source)] and
                step["stdout_sha256"] == expected_sha and
                step["terminal"] is True and step["exit_code"] == 0 and
                step["timeout"] is False,
                f"Libc metadata producer mismatch: {name}")
        metadata.append({
            "name": name, "source_path": str(source),
            "source_sha256": sha(source), "source_digest_md5": source_md5,
            "cabs_path": str(path), "cabs_sha256": expected_sha,
            "cabs_digest_md5": digest,
        })
    expected_argv = inputs.lean_arguments(lean, installed, artifact_dir, receipt["fuel"],
                                           [Path(row["cabs_path"]) for row in cabs])
    require(expected_argv.count("--switches") == 1 and
            expected_argv[expected_argv.index("--switches") + 1] == "gnu_pointer_conversions" and
            "--address-space-top" not in expected_argv,
            "Semantic switch/address-space selection differs")
    if receipt_mode == "ssh-inputs-only":
        require("host_step" not in receipt["ssh_startup"] and
                "native_step" not in receipt["ssh_startup"] and
                all(step["label"].startswith("ssh-cabs-") or step["label"] == "ssh-libc-profile"
                    for step in receipt["steps"]),
                "Inputs-only receipt contains host execution or unrecognized steps")
        host_observation = None
    else:
        host = next((step for step in receipt["steps"]
                     if step["label"] == receipt["ssh_startup"]["host_step"]), None)
        require(host is not None, "Host invocation missing")
        require(host["argv"] == expected_argv,
                "Host argv differs from pinned 90-Cabs order, switches, libc, ABI, or fuel")
        for stream in ("stdout", "stderr"):
            stream_record = host[stream]
            checked_artifact(receipt, stream_record["path"], stream_record["sha256"])
        host_observation = {
            "exit_code": host["exit_code"],
            "residual_processes": host["residual_processes"],
            "stdout_sha256": host["stdout"]["sha256"],
            "stderr_sha256": host["stderr"]["sha256"],
            "observed_version_match": receipt["ssh_startup"]["passed"] is True,
        }
    return {
        "core": {"path": str(core_path), "sha256": sha(core_path)},
        "metadata_order": metadata,
        "profile_path": str(profile_path),
        "profile_sha256": profile_row["sha256"],
    }, expected_argv, host_observation


def build_binding(receipt_path, root=ROOT, runtime=RUNTIME):
    receipt_path = Path(receipt_path)
    root, runtime = Path(root), Path(runtime)
    receipt = json.loads(receipt_path.read_bytes())
    require(receipt["terminal"] is True and
            receipt["artifact_hashes_verified"] is True and
            receipt["identity_before"] == receipt["identity_after"] and
            receipt["artifact_hashes_before"] == receipt["artifact_hashes_after"],
            "Host receipt is not terminal and identity-stable")
    require(receipt["ssh_startup"]["requested"] is True,
            "Receipt did not request 90-TU ssh")
    receipt_mode = receipt.get("mode", "full-host")
    require(receipt_mode in ("full-host", "ssh-inputs-only"), "Unrecognized ssh receipt mode")
    if receipt_mode == "ssh-inputs-only":
        require(receipt["passed"] is True and
                receipt.get("input_provenance_only") is True and
                receipt.get("linked_core_certified") is False and
                receipt.get("linked_execution_verified") is False and
                receipt.get("behavioral_equivalence_proved") is False and
                receipt["ssh_startup"]["passed"] is False and
                receipt["ssh_startup"].get("input_provenance_prepared") is True and
                receipt["ssh_startup"]["status"] == "inputs-prepared",
                "Inputs-only receipt is not a successful provenance-only preparation")
    repo = runtime / "cerberus-lean"
    parser = repo / "_build/default/backend/driver/main.exe"
    lean = repo / "lean_frontend/.lake/build/bin/cerberus-lean"
    installed = repo / "_build/install/default"
    require(sha(runtime / "logs/whole-table-build.json") ==
            receipt["build_receipt_sha256"],
            "Host receipt does not match current checked build")
    check_build(root, runtime, receipt["build_receipt_sha256"])
    plan = inputs.load_inputs(root, runtime, parser)
    require(receipt["ssh_startup"]["inputs"] == plan,
            "Host receipt source/link closure differs from current validated inputs")
    census_path = runtime / "c-import/census.json"
    census = json.loads(census_path.read_bytes())
    cabs = checked_cabs_rows(plan, receipt, census, parser, installed)
    libc, argv, host_observation = checked_libc_profile(
        root, runtime, parser, lean, receipt, cabs, receipt_mode)
    installed_runtime = installed / "lib/cerberus-lib/runtime/libcore"
    std = installed_runtime / "std.core"
    impl = installed_runtime / "impls" / IMPLEMENTATION
    require(sha(std) == sha(repo / "runtime/libcore/std.core") and
            sha(impl) == sha(repo / "runtime/libcore/impls" / IMPLEMENTATION),
            "Installed Core runtime differs from maintained source")
    main = root / "work/cerberus-lean/lean_frontend/Main.lean"
    require(re.search(r'def defaultAddressSpaceTop : Int := 0xFFFFFFFFFFFF\b',
                      main.read_text()) is not None,
            "Address-space default changed; update provenance contract")
    evidence = root / "outputs/openssh-lean/evidence"
    inventory_path = evidence / "source-inventory.json"
    dependencies_path = evidence / "ssh-dependencies.json"
    link_map_path = runtime / "ssh-dependencies/ssh.map"
    build_receipt_path = runtime / "logs/whole-table-build.json"
    cpp_path = Path(plan["cpp_adapter"])
    return {
        "schema_version": 1,
        "scope": "configured-ssh-link-input-provenance",
        "input_provenance_verified": True,
        "linked_core_certified": False,
        "linked_execution_verified": False,
        "host_attempt": host_observation,
        "receipt_mode": receipt_mode,
        "lean_argv_executed": receipt_mode == "full-host",
        "openssh_commit": inputs.PIN,
        "source_inventory_path": str(inventory_path),
        "source_inventory_sha256": sha(inventory_path),
        "census_path": str(census_path),
        "census_sha256": sha(census_path),
        "dependencies_path": str(dependencies_path),
        "dependencies_sha256": sha(dependencies_path),
        "link_map_path": str(link_map_path),
        "link_map_sha256": sha(link_map_path),
        "host_receipt_path": str(receipt_path),
        "host_receipt_sha256": sha(receipt_path),
        "build_receipt_path": str(build_receipt_path),
        "build_receipt_sha256": receipt["build_receipt_sha256"],
        "binding_generator_sha256": sha(Path(__file__)),
        "cpp_adapter": {"path": str(cpp_path), "sha256": sha(cpp_path)},
        "source_binding_helper": {"path": str(SCRIPTS / "ssh_startup_inputs.py"),
                                  "sha256": sha(SCRIPTS / "ssh_startup_inputs.py")},
        "native_ssh": {"path": plan["native"], "sha256": sha(plan["native"])},
        "parser": {"path": str(parser), "sha256": sha(parser)},
        "translator": {"path": str(lean), "sha256": sha(lean),
                       "main_source_sha256": sha(main)},
        "frontend_order": cabs,
        "core_link_order": list(range(89, -1, -1)) + ["libc"],
        "libc": libc,
        "runtime": {
            "std_core": {"path": str(std), "sha256": sha(std)},
            "implementation": {"path": str(impl), "sha256": sha(impl)},
        },
        "semantic_switches": ["gnu_pointer_conversions"],
        "host_abi": "linux-amd64",
        "fuel": receipt["fuel"],
        "address_space_top": ADDRESS_SPACE_TOP,
        "lean_argv": argv,
        "limitations": [
            "Receipt validation binds bytes and producer commands; it is not a proof of preprocessing or C-to-Core semantic correctness.",
            "This is input provenance only. It does not certify that Lean linked or executed these inputs.",
            "A host invocation failure does not turn its input bytes into linked Core evidence.",
            "The closure is for configured native ssh, not other OpenSSH tools or inactive platform branches.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive-receipt-dir", type=Path,
                        help="Preserve the verified build receipt for later cache reuse")
    args = parser.parse_args()
    binding = build_binding(args.receipt)
    if args.archive_receipt_dir is not None:
        directory = args.archive_receipt_dir.resolve()
        directory.mkdir(parents=True, exist_ok=True)
        archived = directory / ("whole-table-build-" + binding["build_receipt_sha256"] + ".json")
        if archived.exists():
            require(sha(archived) == binding["build_receipt_sha256"],
                    "Archived build receipt changed")
        else:
            temporary = directory / (archived.name + ".tmp")
            temporary.write_bytes(Path(binding["build_receipt_path"]).read_bytes())
            require(sha(temporary) == binding["build_receipt_sha256"],
                    "Build receipt changed during archival")
            temporary.replace(archived)
        binding["build_receipt_path"] = str(archived)
    args.output.write_text(json.dumps(binding, sort_keys=True, separators=(",", ":")) + "\n")
    print(json.dumps({"source_binding": str(args.output),
                      "sha256": sha(args.output), "linked_units": len(binding["frontend_order"])}))


if __name__ == "__main__":
    main()
