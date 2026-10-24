#!/usr/bin/env python3
"""Inventory pinned OpenSSH Git blobs; never infer behavioral completeness.

Examples:
  python scripts/inventory.py --source /path/to/openssh-portable --output-dir evidence
  python scripts/inventory.py --source /path/to/openssh-portable --output-dir evidence --require-complete
  python scripts/inventory.py --self-test

Exit codes: 0 inventory generated, 1 input/pin/integrity error, 2 incomplete.
--require-complete intentionally fails until actual conformance verifiers exist.
Existing evidence JSON is never trusted as an input or a proof certificate.
Only Python's standard library and a local Git executable are used.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
import unittest


EXPECTED_COMMIT = "a8c72b842423f0774f542d3c2197247c3dd28d74"
EXPECTED_TAG = "V_10_6_P1"
EXPECTED_TAG_OBJECT = "4cdb6b619315d919e03a6b20a54230340a86b106"
UPSTREAM_URL = "https://github.com/openssh/openssh-portable"
TARBALL_SHA256_BASE64 = "qdyVZd/+hkD2TYY80poyvEo9vewFZqf8RMXW7nZ9Xzk="

MODEL_MAPPINGS = {
    "sshbuf.h": [
        {"module": "OpenSSH/Wire.lean", "selected_operations": [
            "PEEK_U16", "PEEK_U32", "PEEK_U64", "POKE_U16", "POKE_U32", "POKE_U64"]},
        {"module": "OpenSSH/Buffer.lean", "selected_operations": ["SSHBUF_SIZE_MAX constant"]},
    ],
    "sshbuf-getput-basic.c": [
        {"module": "OpenSSH/Wire.lean", "selected_operations": ["check_offset numeric guards (64-bit size_t)"]},
        {"module": "OpenSSH/Buffer.lean", "selected_operations": [
            "sshbuf_get_u8", "sshbuf_get_u16", "sshbuf_get_u32", "sshbuf_get_u64",
            "sshbuf_peek_string_direct", "sshbuf_get_string_direct", "sshbuf_get_string", "sshbuf_get_cstring"]},
    ],
    "ssherr.h": [
        {"module": "OpenSSH/Wire.lean", "selected_operations": ["selected numeric error constants"]},
        {"module": "OpenSSH/Buffer.lean", "selected_operations": ["selected numeric error constants"]},
    ],
}

MISSING_OBLIGATIONS = (
    ("c_reference_semantics", "Machine-checked C and library semantics linked to the pinned executable."),
    ("reference_to_model_proof", "A checked reference-to-Lean proof for every admitted behavior, with source linkage."),
    ("model_to_reference_proof", "A checked Lean-to-reference proof excluding additional behavior."),
    ("complete_lean_runtime", "Executable Lean replacements for every distribution program and required helper."),
    ("environment_and_effects", "Validated OS, heap, ABI, dependency, entropy, scheduling, device, and effect models."),
    ("all_platform_build_variants", "Discharged obligations for every admitted platform and feature combination."),
    ("liveness_and_divergence", "Termination, deadlock, fairness, responsiveness, and infinite-trace correspondence."),
    ("timing_and_distributions", "The timing, resource, and probabilistic equivalence required by the observer contract."),
    ("whole_upstream_regression", "A complete regression receipt with verified Lean executable substitution and no unexplained skips."),
    ("compiled_implementation_link", "Evidence linking Lean semantics and effects to the actual distributed executables."),
    ("completion_certificate_verifier", "An implemented verifier for the preceding evidence; status strings are not certificates."),
)


class InventoryError(RuntimeError):
    pass


def git(source: Path, *args: str, stdin: bytes | None = None) -> bytes:
    result = subprocess.run(
        ["git", "--no-replace-objects", "-C", str(source), *args],
        input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if result.returncode:
        raise InventoryError("git " + " ".join(args) + ": " + result.stderr.decode("utf-8", "replace").strip())
    return result.stdout


def validate_pin_values(head: str, tag_object: str, tag_commit: str) -> None:
    expected = (("HEAD", head, EXPECTED_COMMIT),
                ("tag object", tag_object, EXPECTED_TAG_OBJECT),
                ("peeled tag commit", tag_commit, EXPECTED_COMMIT))
    for label, actual, required in expected:
        if actual != required:
            raise InventoryError(f"Pinned {label} mismatch: expected {required}, got {actual}")


def read_pin(source: Path) -> str:
    head = git(source, "rev-parse", "--verify", "HEAD^{commit}").decode().strip()
    tag_object = git(source, "rev-parse", "--verify", f"refs/tags/{EXPECTED_TAG}").decode().strip()
    tag_commit = git(source, "rev-parse", "--verify", f"refs/tags/{EXPECTED_TAG}^{{commit}}").decode().strip()
    validate_pin_values(head, tag_object, tag_commit)
    if git(source, "cat-file", "-t", EXPECTED_TAG_OBJECT).strip() != b"tag":
        raise InventoryError("Pinned tag object is not an annotated tag")
    return git(source, "rev-parse", f"{EXPECTED_COMMIT}^{{tree}}").decode().strip()


def read_entries(source: Path) -> list[dict]:
    raw = git(source, "ls-tree", "-r", "-z", "--full-tree", EXPECTED_COMMIT)
    entries = []
    for record in raw.split(b"\0"):
        if not record:
            continue
        header, name = record.split(b"\t", 1)
        mode, kind, oid = header.decode("ascii").split()
        if kind != "blob":
            raise InventoryError(f"Unsupported tracked object {name!r}: {kind}; nested sources require their own pin")
        entries.append({"path": name.decode("utf-8", "surrogateescape"), "git_mode": mode,
                        "git_object_type": kind, "git_blob_oid": oid})
    return sorted(entries, key=lambda entry: entry["path"])


def read_blobs(source: Path, object_ids: list[str]) -> dict[str, bytes]:
    unique = sorted(set(object_ids))
    output = git(source, "cat-file", "--batch", stdin=("\n".join(unique) + "\n").encode("ascii"))
    offset = 0
    blobs = {}
    for oid in unique:
        end = output.find(b"\n", offset)
        if end < 0:
            raise InventoryError("Truncated git batch header")
        fields = output[offset:end].split()
        if len(fields) != 3 or fields[0].decode() != oid or fields[1] != b"blob":
            raise InventoryError(f"Unexpected batch response for {oid}: {fields!r}")
        size = int(fields[2])
        start = end + 1
        blob = output[start:start + size]
        if len(blob) != size or output[start + size:start + size + 1] != b"\n":
            raise InventoryError(f"Truncated Git blob {oid}")
        actual_oid = hashlib.sha1(f"blob {size}\0".encode("ascii") + blob).hexdigest()
        if actual_oid != oid:
            raise InventoryError(f"Git blob integrity mismatch for {oid}")
        blobs[oid] = blob
        offset = start + size + 1
    if offset != len(output):
        raise InventoryError("Unexpected bytes following Git batch response")
    return blobs


def categories(path: str, data: bytes) -> list[str]:
    p = PurePosixPath(path)
    result = set()
    if p.suffix == ".c":
        result.add("c_compilation_unit")
    if p.suffix == ".h":
        result.add("c_header")
    if p.suffix in (".cc", ".cpp", ".cxx"):
        result.add("cpp_compilation_unit")
    if p.name.startswith("PROTOCOL"):
        result.add("protocol_document")
    if re.search(r"\.[1-9]$", path):
        result.add("manual_page")
    if path.startswith("regress/") or path.startswith("openbsd-compat/regress/"):
        result.add("regression_artifact")
        if p.suffix == ".sh":
            result.add("regression_shell_script")
        if "testdata" in p.parts or p.suffix in (".in", ".out", ".pub", ".pem", ".key"):
            result.add("regression_fixture")
    if "fuzz" in path:
        result.add("fuzz_artifact")
    if path.startswith("openbsd-compat/"):
        result.add("portability_artifact")
    if path.startswith(".github/"):
        result.add("ci_artifact")
    if p.name.startswith("Makefile") or p.suffix in (".mk", ".m4") or p.name in ("configure", "configure.ac", ".depend"):
        result.add("build_definition")
    if p.name in ("ssh_config", "sshd_config", "config.h.in", "configure", "configure.ac") or p.suffix == ".in":
        result.add("configuration_input")
    if p.suffix == ".sh" or data.startswith(b"#!/bin/sh") or data.startswith(b"#!/usr/bin/env bash"):
        result.add("shell_script")
    if p.name.startswith("README") or p.name in ("INSTALL", "OVERVIEW", "ChangeLog", "CREDITS", "TODO") or p.suffix in (".md", ".txt"):
        result.add("documentation")
    if p.name.upper() in ("LICENCE", "LICENSE", "COPYING"):
        result.add("license")
    return sorted(result or {"other_tracked_file"})


def make_variable(data: bytes, variable: str) -> list[str]:
    text = data.decode("utf-8", "replace").replace("\\\n", " ")
    values = []
    pattern = re.compile(r"^" + re.escape(variable) + r"\s*(\+?=)\s*(.*)$", re.MULTILINE)
    for match in pattern.finditer(text):
        if match.group(1) == "=":
            values = []
        values.extend(match.group(2).split("#", 1)[0].split())
    return values


def coverage_status(inventory: dict, generator_sha256: str) -> dict:
    # This function regenerates facts from the generator and source inventory.
    # It does not load an editable status file or accept a Boolean certificate.
    return {
        "schema_version": 1,
        "upstream_commit": EXPECTED_COMMIT,
        "generator_sha256": generator_sha256,
        "whole_program_equivalence": False,
        "completion_status": "incomplete",
        "semantic_coverage_percentage": None,
        "semantic_coverage_percentage_reason": "There is no established denominator of all behaviors; file inventory is not semantic coverage.",
        "runtime_programs_implemented": [],
        "runtime_programs_fully_equivalent": [],
        "source_files_with_whole_file_equivalence_proofs": [],
        "source_registry": {
            "tracked_file_count": inventory["summary"]["tracked_file_count"],
            "c_compilation_unit_count": inventory["summary"]["c_compilation_unit_count"],
            "complete_for_pinned_git_tree": True,
            "meaning": "Every tracked Git blob has an entry; this makes no behavioral completeness claim.",
        },
        "model_only_mappings": [
            {"upstream_path": path, "mappings": mappings,
             "status": "selected_content_model_only", "whole_file_equivalence": False,
             "c_to_lean_equivalence_proved": False}
            for path, mappings in sorted(MODEL_MAPPINGS.items())
        ],
        "model_scope_limitations": [
            "Wire uses a selected 64-bit size_t model and does not establish pointer or heap semantics.",
            "Buffer assumes sane immutable unread bytes and models allocation outcome as an explicit input.",
            "Internal Lean theorems are not a checked derivation from the C reference semantics.",
            "Refinement is a generic finite input-trace framework without an OpenSSH reference instance.",
        ],
        "required_completion_evidence": [
            {"id": key, "status": "missing", "validator": "not_implemented", "required": description}
            for key, description in MISSING_OBLIGATIONS
        ],
        "completion_gate": {
            "accepts_status_json_as_certificate": False,
            "implementation": "The generator reconstructs missing obligations and refuses certification; no completion verifier exists yet.",
            "require_complete_exit_code": 2,
        },
        "regression_evidence": {
            "whole_upstream_suite_against_lean": "not_established",
            "actual_lean_executable_substitution": "not_established",
            "all_required_optional_cases_run": "not_established",
            "note": "Narrow component tests, if recorded elsewhere, do not discharge this whole-suite obligation.",
        },
    }


def write_json(path: Path, document: dict) -> None:
    data = (json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("utf-8")
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + ".", suffix=".tmp", delete=False) as handle:
        temporary = Path(handle.name)
        handle.write(data)
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def generate(source: Path, output_dir: Path) -> dict:
    tree = read_pin(source)
    entries = read_entries(source)
    blobs = read_blobs(source, [entry["git_blob_oid"] for entry in entries])
    by_path = {}
    counts = Counter()
    total_bytes = 0
    for entry in entries:
        data = blobs[entry["git_blob_oid"]]
        by_path[entry["path"]] = data
        entry["byte_length"] = len(data)
        entry["sha256"] = hashlib.sha256(data).hexdigest()
        entry["categories"] = categories(entry["path"], data)
        entry["selected_model_mappings"] = MODEL_MAPPINGS.get(entry["path"], [])
        entry["whole_file_equivalence_proved"] = False
        counts.update(entry["categories"])
        total_bytes += len(data)
    if not set(MODEL_MAPPINGS).issubset(by_path):
        raise InventoryError("A selected model mapping refers to a path absent from the pinned source")
    generator_sha256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    inventory = {
        "schema_version": 1, "upstream_commit": EXPECTED_COMMIT, "upstream_tree": tree,
        "generator_sha256": generator_sha256,
        "content_basis": "Raw immutable Git blob bytes, not checkout bytes or generated build files.",
        "hash_policy": "SHA256 covers exactly each blob payload; git_blob_oid is independently checked as Git SHA1(blob header + payload).",
        "category_policy": "Overlapping filename/path classifications; .c inventory includes tests, compatibility code, and any tracked generated C, without claiming every file is compiled in every build.",
        "summary": {"tracked_file_count": len(entries), "unique_git_blob_count": len(blobs),
                    "total_blob_bytes_counting_paths": total_bytes,
                    "c_compilation_unit_count": counts["c_compilation_unit"],
                    "category_counts": dict(sorted(counts.items()))},
        "upstream_regression_inventory": {
            "LTESTS": make_variable(by_path["regress/Makefile"], "LTESTS"),
            "INTEROP_TESTS": make_variable(by_path["regress/Makefile"], "INTEROP_TESTS"),
            "EXTRA_TESTS": make_variable(by_path["regress/Makefile"], "EXTRA_TESTS"),
            "REGRESS_TARGETS": make_variable(by_path["regress/Makefile"], "REGRESS_TARGETS"),
            "execution_status": "inventory_only_not_a_test_receipt",
        },
        "files": entries,
    }
    pin = {
        "schema_version": 1, "project": "OpenSSH Portable", "release": "10.6p1",
        "release_date": "2026-10-06", "upstream_url": UPSTREAM_URL,
        "tag": EXPECTED_TAG, "tag_object": EXPECTED_TAG_OBJECT,
        "commit": EXPECTED_COMMIT, "tree": tree,
        "validation": {"head_matches": True, "tag_object_matches": True, "peeled_tag_matches": True,
                       "blob_object_hashes_verified": True, "release_signature_verified": False,
                       "note": "Object identity and local blob integrity checked; no GPG or SSH signature verification is claimed."},
        "release_tarball": {
            "url": "https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-10.6p1.tar.gz",
            "sha256_base64_published": TARBALL_SHA256_BASE64,
            "checksum_source": "https://www.openssh.org/releasenotes.html",
            "tarball_download_and_hash_verified_by_this_script": False,
        },
        "inventory_policy": "Only objects reachable as tracked files from the pinned commit are inventoried. Checkout line-ending conversion, untracked files, generated config.h, and local build products cannot alter this inventory.",
        "generator_sha256": generator_sha256,
    }
    status = coverage_status(inventory, generator_sha256)
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "source-inventory.json", inventory)
    write_json(output_dir / "upstream-pin.json", pin)
    write_json(output_dir / "coverage-status.json", status)
    return inventory


def self_test() -> bool:
    class InventoryTests(unittest.TestCase):
        def test_correct_pin(self):
            validate_pin_values(EXPECTED_COMMIT, EXPECTED_TAG_OBJECT, EXPECTED_COMMIT)

        def test_tampered_commit_rejected(self):
            with self.assertRaisesRegex(InventoryError, "HEAD mismatch"):
                validate_pin_values("0" * 40, EXPECTED_TAG_OBJECT, EXPECTED_COMMIT)

        def test_tampered_tag_rejected(self):
            with self.assertRaisesRegex(InventoryError, "tag object mismatch"):
                validate_pin_values(EXPECTED_COMMIT, "0" * 40, EXPECTED_COMMIT)

        def test_wrong_peeled_commit_rejected(self):
            with self.assertRaisesRegex(InventoryError, "peeled tag commit mismatch"):
                validate_pin_values(EXPECTED_COMMIT, EXPECTED_TAG_OBJECT, "0" * 40)

        def test_make_append_and_continuation(self):
            self.assertEqual(make_variable(b"X= a \\\n b\n#X+= bad\nX+= c # comment\n", "X"), ["a", "b", "c"])

        def test_status_does_not_certify_registry(self):
            document = coverage_status({"summary": {"tracked_file_count": 2000, "c_compilation_unit_count": 500}}, "test")
            self.assertFalse(document["whole_program_equivalence"])
            self.assertEqual(document["runtime_programs_implemented"], [])
            self.assertTrue(all(item["status"] == "missing" for item in document["required_completion_evidence"]))
            document["whole_program_equivalence"] = True
            regenerated = coverage_status({"summary": {"tracked_file_count": 2000, "c_compilation_unit_count": 500}}, "test")
            self.assertFalse(regenerated["whole_program_equivalence"])

    return unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(InventoryTests)).wasSuccessful()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", type=Path, help="Local pinned OpenSSH Portable Git repository")
    parser.add_argument("--output-dir", type=Path, help="Directory for the three generated evidence JSON files")
    parser.add_argument("--require-complete", action="store_true", help="Fail because the current work lacks whole-program conformance evidence")
    parser.add_argument("--self-test", action="store_true", help="Run pin rejection and inventory/gate contract tests")
    args = parser.parse_args()
    if args.self_test:
        return 0 if self_test() else 1
    if args.source is None or args.output_dir is None:
        parser.error("--source and --output-dir are required unless --self-test is used")
    try:
        inventory = generate(args.source, args.output_dir)
    except (InventoryError, OSError, ValueError) as error:
        print(f"Inventory rejected: {error}", file=sys.stderr)
        return 1
    summary = inventory["summary"]
    print(f"Inventoried {summary['tracked_file_count']} tracked files, {summary['c_compilation_unit_count']} C compilation units; semantic coverage is unestablished.")
    if args.require_complete:
        # This refusal is derived from actual missing verifier capabilities,
        # never from user-editable 'proved'/'complete' status flags in JSON.
        print("INCOMPLETE: no completion certificate verifier exists; missing obligations:", file=sys.stderr)
        for key, description in MISSING_OBLIGATIONS:
            print(f"  {key}: {description}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
