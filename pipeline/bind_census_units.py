#!/usr/bin/env python3
"""Bind every pinned C census TU to a checked one-unit Core export.

Archive-only units additionally verify exact native archive membership.
The bindings are source-record inputs, not whole-program behavior claims.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = Path(__file__).resolve().parents[1] / "local/runtime"
REFERENCE = ROOT / "work/reference-source"
sys.path.insert(0, str(ROOT / "work"))
import build_guard
from bind_export_targets import (checked, checked_imports, load_inputs,
                                 require, sha)
from export_target_inventory import object_index
from linked_source_binding import cabs_digest, md5
from run_pointer_check_plan import check_build
sys.path.insert(0, str(ROOT / "outputs/openssh-lean/scripts"))
import ssh_startup_inputs as inputs


def archive_for(source):
    name = ("openbsd-compat/libopenbsd-compat.a" if
            source.startswith("openbsd-compat/") else "libssh.a")
    return REFERENCE / name


def bind_one(source, ordinal, manifest_path, manifest, shared_path, shared,
             imports, unit, object_path, archive_hashes, archive_members,
             linked_object_hashes):
    archive_only = source in manifest["unlinked_census_sources"]
    checked(object_path, sha(object_path), "Compiled object")
    if archive_only:
        archive = archive_for(source)
        member = object_path.name
        require(member in archive_members[archive] and
                archive_members[archive].count(member) == 1,
                f"{source}: missing or duplicate archive member")
        archived_bytes = subprocess.check_output(["ar", "p", str(archive), member])
        require(hashlib.sha256(archived_bytes).hexdigest() == sha(object_path),
                f"{source}: archive member differs from compiled object")
    else:
        require((source, str(object_path), sha(object_path)) in linked_object_hashes,
                f"{source}: object differs from configured native link input")
    pre = unit["preprocessing"]
    checked(unit["file"], unit["source_sha256"], "Original C source")
    checked(pre["path"], pre["sha256"], "Preprocessed source")
    imported = imports[source]
    require(imported["source_sha256"] == unit["source_sha256"] and
            imported["preprocessed_sha256"] == pre["sha256"],
            f"{source}: cached Cabs input identity differs")
    parser_row = imported["parser"]
    cabs = parser_row["stdout_path"]
    checked(cabs, parser_row["stdout_sha256"], "Cabs input")
    parser = shared["parser"]["path"]
    installed = RUNTIME / "cerberus-lean/_build/install/default"
    cpp = shared["cpp_adapter"]["path"]
    require(parser_row["exit_code"] == 0 and not parser_row["timed_out"] and
            parser_row["arguments"] == inputs.cabs_arguments(
                Path(parser), installed, Path(cpp), Path(pre["path"])) and
            Path(cabs).resolve().is_relative_to(RUNTIME / "import-fork/units") and
            cabs_digest(cabs) == md5(pre["path"]),
            f"{source}: Cabs did not come from the pinned preprocessing")
    frontend = [{
        "source": source,
        "original_path": unit["file"],
        "original_sha256": unit["source_sha256"],
        "preprocessed_path": pre["path"],
        "preprocessed_sha256": pre["sha256"],
        "preprocessed_digest_md5": md5(pre["path"]),
        "cabs_path": cabs,
        "cabs_sha256": parser_row["stdout_sha256"],
        "cabs_digest_md5": cabs_digest(cabs),
        "parser_argv": parser_row["arguments"],
    }]
    old_count = len(shared["frontend_order"])
    prior = shared["lean_argv"]
    require(old_count > 0 and prior[-old_count:] ==
            [row["cabs_path"] for row in shared["frontend_order"]],
            "Shared binding does not end in its ordered Cabs inputs")
    target = f"unit-{ordinal:03d}"
    binding = {
        "schema_version": 2,
        "scope": "pinned-openssh-census-unit-input-provenance",
        "target": target,
        "receipt_mode": "census-unit-input-only",
        "input_provenance_verified": True,
        "linked_core_certified": False,
        "linked_execution_verified": False,
        "behavioral_equivalence_proved": False,
        "lean_argv_executed": False,
        "openssh_commit": inputs.PIN,
        "source_class": ("archive-only" if archive_only else
                         "configured-executable-link"),
        "compiled_object": {
            "object_path": str(object_path),
            "object_sha256": sha(object_path),
            "source": source,
        },
        "target_manifest_path": str(manifest_path),
        "target_manifest_sha256": sha(manifest_path),
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
        "core_link_order": [0, "libc"],
        "libc": shared["libc"],
        "runtime": shared["runtime"],
        "semantic_switches": shared["semantic_switches"],
        "host_abi": shared["host_abi"],
        "fuel": shared["fuel"],
        "address_space_top": shared["address_space_top"],
        "lean_argv": prior[:-old_count] + [cabs],
        "limitations": [
            "The one-unit-plus-libc Core link is not a native executable closure.",
            "Input identity and a closed Core quote do not prove C translation or behavior.",
        ],
    }
    if archive_only:
        binding["archive_member"] = {
            "archive_path": str(archive),
            "archive_sha256": archive_hashes[archive],
            "member": member,
            "object_path": str(object_path),
            "object_sha256": sha(object_path),
            "source": source,
        }
    return binding


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
        census = json.loads(Path(manifest["census_path"]).read_bytes())
        index = object_index(census["translation_units"])
        by_source = {row["source"]: (row, path) for path, row in index.items()}
        missing = manifest["unlinked_census_sources"]
        linked = manifest["linked_source_union"]
        require(len(missing) == manifest["unlinked_census_count"] and
                len(set(missing)) == len(missing) and
                len(linked) == manifest["linked_source_union_count"] and
                set(missing).isdisjoint(linked) and
                set(missing) | set(linked) == set(by_source) and
                len(by_source) == manifest["census_unit_count"],
                "Native link closure and unlinked census do not partition the census")
        archives = {archive_for(source) for source in missing}
        archive_hashes = {archive: sha(archive) for archive in archives}
        archive_members = {archive: subprocess.check_output(
            ["ar", "t", str(archive)], text=True).splitlines()
            for archive in archives}
        linked_object_hashes = {
            (unit["source"], unit["object_path"], unit["object_sha256"])
            for target in manifest["targets"] for unit in target["units"]}
        output.mkdir()
        rows = []
        for ordinal, source in enumerate(sorted(by_source), 1):
            unit, object_path = by_source[source]
            binding = bind_one(source, ordinal, manifest_path, manifest,
                               shared_path, shared, imports, unit, object_path,
                               archive_hashes, archive_members,
                               linked_object_hashes)
            path = output / (binding["target"] + ".json")
            path.write_text(json.dumps(binding, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8")
            rows.append({"target": binding["target"], "source": source,
                         "source_class": binding["source_class"],
                         "linked_units": 1, "path": str(path), "sha256": sha(path)})
        receipt = {
            "schema_version": 1,
            "scope": "all-pinned-census-unit-input-bindings",
            "manifest_path": str(manifest_path),
            "manifest_sha256": sha(manifest_path),
            "shared_libc_binding_path": str(shared_path),
            "shared_libc_binding_sha256": sha(shared_path),
            "import_report_path": str(imports_path),
            "import_report_sha256": sha(imports_path),
            "build_receipt_sha256": shared["build_receipt_sha256"],
            "census_sha256": manifest["census_sha256"],
            "linked_source_count": len(linked),
            "archive_only_count": len(missing),
            "census_unit_count": len(by_source),
            "targets": rows,
            "timing": {"total_seconds": round(time.monotonic() - started, 3)},
        }
        receipt_path = output / "bindings.json"
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                                encoding="utf-8")
        print(json.dumps({"archive_only": len(missing),
                          "census": len(by_source),
                          "bindings": str(receipt_path)}), flush=True)


if __name__ == "__main__":
    main()
