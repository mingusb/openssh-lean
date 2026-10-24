"""Stable identity for checked Core exports across release-run directories.

The identity names the bytes and semantic profile consumed by the pinned
frontend. A reused artifact retains its original binding and is verified again
before use; this key alone is not a proof of C/Core equivalence.
"""
import hashlib
import json


def semantic_identity(binding):
    return {
        "target": binding["target"],
        "scope": binding["scope"],
        "receipt_mode": binding["receipt_mode"],
        "openssh_commit": binding["openssh_commit"],
        "source_class": binding.get("source_class"),
        "build_receipt_sha256": binding["build_receipt_sha256"],
        "translator_sha256": binding["translator"]["sha256"],
        "parser_sha256": binding["parser"]["sha256"],
        "runtime": {
            name: {"path": value["path"], "sha256": value["sha256"]}
            for name, value in binding["runtime"].items()
        },
        "libc_core_sha256": binding["libc"]["core"]["sha256"],
        "libc_metadata": [
            (row["name"], row["cabs_sha256"], row["cabs_digest_md5"],
             row["source_sha256"])
            for row in binding["libc"]["metadata_order"]
        ],
        "frontend_order": [
            (row["source"], row["original_sha256"],
             row["preprocessed_sha256"], row["cabs_sha256"],
             row["cabs_digest_md5"])
            for row in binding["frontend_order"]
        ],
        "core_link_order": binding["core_link_order"],
        "address_space_top": binding["address_space_top"],
        "fuel": binding["fuel"],
        "host_abi": binding["host_abi"],
        "semantic_switches": binding["semantic_switches"],
    }


def semantic_key(binding):
    payload = json.dumps(semantic_identity(binding), sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()
