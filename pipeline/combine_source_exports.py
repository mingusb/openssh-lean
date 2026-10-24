#!/usr/bin/env python3
"""Require one checked single-unit Core record for every pinned census TU.

This is source-record coverage, not a linked executable or a C/Lean proof.
"""
import argparse
import hashlib
import json
from pathlib import Path
import time
from core_export_identity import semantic_key

RUNTIME = Path(__file__).resolve().parents[1] / "local/runtime"


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def checked(path, expected, label):
    require(Path(path).is_file() and sha(path) == expected,
            f"{label} differs: {path}")


def read(path):
    return json.loads(Path(path).read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--source-exports", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.absolute()
    require(output.parent == RUNTIME and not output.exists() and
            not output.is_symlink(), "Use a fresh direct runtime output")
    started = time.monotonic()
    manifest_path = args.manifest.resolve(strict=True)
    manifest = read(manifest_path)
    checked(manifest["census_path"], manifest["census_sha256"], "C census")
    census = read(manifest["census_path"])
    require(manifest["scope"] == "configured-pinned-openssh-native-link-closures" and
            manifest["census_unit_count"] == len(census["translation_units"]),
            "Wrong native target manifest or census")
    report = read(args.source_exports)
    require(report["terminal"] is True and report["passed"] is True and
            report["scope"] == "all OpenSSH census unit Core snapshots" and
            report["target_count"] == report["passed_count"] ==
            len(report["targets"]) == manifest["census_unit_count"] and
            report["build_receipt_sha256"] == manifest["build_receipt_sha256"],
            "Incomplete or stale census Core export")
    binding_receipt_path = report["binding_receipt_path"]
    checked(binding_receipt_path, report["binding_receipt_sha256"],
            "Census binding receipt")
    bindings = read(binding_receipt_path)
    require(bindings["scope"] == "all-pinned-census-unit-input-bindings" and
            bindings["manifest_sha256"] == sha(manifest_path) and
            bindings["census_unit_count"] == len(bindings["targets"]) ==
            manifest["census_unit_count"],
            "Census binding receipt does not match the inventory")
    results = {}
    for item in report["targets"]:
        require(item["terminal"] is True and item["passed"] is True and
                item["output_present"] is True and
                item["target"] not in results,
                "Incomplete or duplicate per-unit output")
        checked(item["binding_path"], item["binding_sha256"], "Binding")
        checked(item["output"], item["output_sha256"], "Core output")
        results[item["target"]] = item
    census_rows = {unit["source"]: unit for unit in census["translation_units"]}
    linked = set(manifest["linked_source_union"])
    unlinked = set(manifest["unlinked_census_sources"])
    require(len(census_rows) == manifest["census_unit_count"] and
            linked.isdisjoint(unlinked) and
            linked | unlinked == set(census_rows),
            "Native source partition is not the full census")
    coverage = {}
    translator_hashes = set()
    prior_reports = {}
    for row in bindings["targets"]:
        source = row["source"]
        require(source in census_rows and source not in coverage and
                row["target"] in results and row["linked_units"] == 1,
                "Missing or duplicate bound census source")
        checked(row["path"], row["sha256"], "Per-unit source binding")
        binding = read(row["path"])
        result = results[row["target"]]
        current_key = semantic_key(binding)
        require(result.get("semantic_key", current_key) == current_key,
                "Core export semantic identity differs from current binding")
        if "reused_from_result_path" in result:
            prior_path = result["reused_from_result_path"]
            prior_sha = result["reused_from_result_sha256"]
            if prior_path not in prior_reports:
                checked(prior_path, prior_sha, "Cached Core export receipt")
                prior_report = read(prior_path)
                require(prior_report["terminal"] is True and
                        prior_report["passed"] is True,
                        "Cached Core export receipt did not pass")
                prior_reports[prior_path] = (
                    prior_sha, prior_report,
                    {item["target"]: item for item in prior_report["targets"]})
            cached_sha, prior_report, prior_by_target = prior_reports[prior_path]
            require(prior_sha == cached_sha,
                    "Inconsistent cached Core receipt hash")
            prior_rows = ([prior_by_target[row["target"]]]
                          if row["target"] in prior_by_target else [])
            require(prior_report["terminal"] is True and
                    prior_report["passed"] is True and
                    len(prior_rows) == 1 and prior_rows[0]["passed"] is True and
                    prior_rows[0]["output"] == result["output"] and
                    prior_rows[0]["output_sha256"] == result["output_sha256"],
                    "Cached Core export is not the checked prior result")
            artifact_binding_path = result["artifact_binding_path"]
            checked(artifact_binding_path, result["artifact_binding_sha256"],
                    "Cached Core source binding")
            prior_binding = read(artifact_binding_path)
            require(semantic_key(prior_binding) == current_key and
                    prior_rows[0].get("artifact_binding_sha256",
                                      prior_rows[0]["binding_sha256"]) ==
                    result["artifact_binding_sha256"],
                    "Cached Core source binding differs semantically")
        unit = binding["frontend_order"][0]
        census_unit = census_rows[source]
        expected_class = ("configured-executable-link" if source in linked else
                          "archive-only")
        require(binding["scope"] ==
                "pinned-openssh-census-unit-input-provenance" and
                binding["target"] == row["target"] == result["target"] and
                binding["source_class"] == row["source_class"] == expected_class and
                len(binding["frontend_order"]) == 1 and
                unit["source"] == source and
                unit["original_sha256"] == census_unit["source_sha256"] and
                unit["preprocessed_sha256"] ==
                census_unit["preprocessing"]["sha256"] and
                result["binding_sha256"] == row["sha256"],
                f"Source or binding identity drift: {source}")
        translator_hashes.add(binding["translator"]["sha256"])
        coverage[source] = {
            "class": expected_class,
            "target": row["target"],
            "output": result["output"],
            "output_sha256": result["output_sha256"],
            "semantic_key": current_key,
            "artifact_binding_path": result.get("artifact_binding_path",
                                                result["binding_path"]),
            "reused": "reused_from_result_path" in result,
            "original_sha256": unit["original_sha256"],
            "preprocessed_sha256": unit["preprocessed_sha256"],
            "cabs_sha256": unit["cabs_sha256"],
        }
    require(set(coverage) == set(census_rows) and
            set(results) == {row["target"] for row in bindings["targets"]} and
            len(translator_hashes) == 1,
            "Core exports do not account for the entire pinned census")
    for prior_path, (prior_sha, _, _) in prior_reports.items():
        checked(prior_path, prior_sha, "Cached Core export receipt at completion")
    output.write_text(json.dumps({
        "schema_version": 1,
        "scope": "all-pinned-census-source-Core-record-exports",
        "complete": True,
        "census_unit_count": len(coverage),
        "executable_link_unit_count": len(linked),
        "archive_only_unit_count": len(unlinked),
        "translator_sha256": next(iter(translator_hashes)),
        "build_receipt_sha256": manifest["build_receipt_sha256"],
        "manifest_path": str(manifest_path),
        "manifest_sha256": sha(manifest_path),
        "source_export_receipt": str(args.source_exports),
        "source_export_receipt_sha256": sha(args.source_exports),
        "sources": {source: coverage[source] for source in sorted(coverage)},
        "whole_program_link_verified": False,
        "behavioral_equivalence_proved": False,
        "lean_kernel_import_verified": False,
        "timing": {"total_seconds": round(time.monotonic() - started, 3)},
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"complete": True, "source_units": len(coverage),
                      "executable_link_units": len(linked),
                      "archive_only_units": len(unlinked),
                      "receipt": str(output)}), flush=True)


if __name__ == "__main__":
    main()
