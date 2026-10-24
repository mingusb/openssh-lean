"""Emit a checked, content-addressed Lean/native stack-fault obligation.

The Lean theorem proves failure in an explicit stack-reservation machine.
This command verifies its artifacts and identifiers, then records the
separate premises needed to infer a native SIGSEGV from original C.
"""
import argparse
import base64
import hashlib
import json
import os
import re
import resource
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "search"))
from core_index import Index  # noqa: E402
from fault_source_map import _core_site_identity  # noqa: E402

SOURCE = Path(__file__).with_name("StackFault.lean")
SOURCE_SHA = "50b155c03e8c2c1533d852afa54b032b9da7025871fe28cfcafa50b218b3093b"
SCANNER = Path(__file__).with_name("scan_archive.py")
C_SOURCE = ROOT / "work/reference-source/scp.c"
BINARY = ROOT / "work/reference-source/scp"
PROFILE = ROOT / "search/recursion/scp-recursive-sink.json"
RECEIPT = ROOT / (
    "local/search/catalog/native-observations/"
    "8a20ff732a8a45d394af1fc800aab6be/receipt.json"
)
DEFAULT_OUTPUT = ROOT / "local/search/recursion-campaign/stack-obligations"
LEAN = ROOT / "work/lean-4.32.2-linux/bin/lean"
C_SHA = "2bdd019495f36361345801a8ee61c2ea16db9e4d35e368b3d50557a8f875562b"
ELF_SHA = "ccec78d50c244df96f2cbcc61fdb0b44bb18330c5ea3368189f80029b3778f28"
ALIAS_SHA = "a9065dc242c6c6e5e91ffaa31f31cacc452433870d0fe39d7a93a25c92797bbf"
NAMED_SITE_SHA = "5b849417d044322bcac7180deb17649d6572bfa881e2fef3415d323ccd1c2aca"
ALIAS_SITE_SHA = "5ed231e3c7e9263a623bc6b996ce1b5a3c7b88bd7df7fece43456aff49de789d"
CATALOG_REPRODUCER_ID = "3be34d318643dccef7fe9215737fe49f2b93d4e12749b213b632b98a3533e987"
CATALOG_SCRIPT_SHA = "f9dcf2db1d94b640ace826661efc72d9a9c9ed102cba79dc15f6344b65892a64"
DEPTH = 2048
RECORD = b"D0700 0 x\n"
FIRST_SUB = (0x820e, bytes.fromhex("4881ec00100000"), 4096)
SECOND_SUB = (0x821a, bytes.fromhex("4881ec88010000"), 392)
THEOREMS = (
    "RecursionSearch.StackFault.reserveFault_of_shortfall",
    "RecursionSearch.StackFault.witnessInput_length",
    "RecursionSearch.StackFault.scp_reservation_exceeds_soft_limit",
    "RecursionSearch.StackFault.scp_abstract_stack_fault_if_depth_exceeds",
    "RecursionSearch.StackFault.scp_abstract_stack_fault_for_any_budget",
    "RecursionSearch.StackFault.scp_witness_input_length",
)
# Lean's standard logical axioms; an admitted proof or project axiom is not
# acceptable evidence for this obligation.
ALLOWED_AXIOMS = frozenset({"propext", "Quot.sound", "Classical.choice"})


def sha(data):
    return hashlib.sha256(data).hexdigest()


def need(condition, reason):
    if not condition:
        raise RuntimeError(reason)


def run_checked(command, timeout=180):
    result = subprocess.run(command, cwd=ROOT, capture_output=True,
                            text=True, timeout=timeout)
    need(result.returncode == 0,
         "Command failed: " + " ".join(map(str, command)) + "\n"
         + result.stdout[-2000:] + result.stderr[-2000:])
    return result


def checked_lean():
    # Re-elaborate the exact source and query the dependencies of every theorem
    # named in the obligation. A quiet `lean file.lean` exit alone would also
    # accept a theorem proved from a newly declared custom axiom.
    source_bytes = SOURCE.read_bytes()
    need(sha(source_bytes) == SOURCE_SHA, "Pinned Lean stack theorem source changed")
    queries = "\n" + "\n".join("#print axioms " + name for name in THEOREMS) + "\n"
    with tempfile.TemporaryDirectory(prefix="scp-stack-axioms-") as directory:
        probe = Path(directory) / "StackFaultAxioms.lean"
        probe.write_bytes(source_bytes + queries.encode())
        result = run_checked([str(LEAN), str(probe)], timeout=120)
    need(not result.stderr.strip(), "Lean proof had unexpected diagnostics")
    rows = result.stdout.strip().splitlines()
    need(len(rows) == len(THEOREMS), "Lean axiom report is incomplete")
    for name, row in zip(THEOREMS, rows):
        dependencies = set()
        if row != f"'{name}' does not depend on any axioms":
            match = re.fullmatch(
                r"'([^']+)' depends on axioms: \[(.*)\]", row)
            need(match is not None and match.group(1) == name,
                 "Lean axiom report names another theorem")
            dependencies = set(match.group(2).split(", ")) if match.group(2) else set()
        need(dependencies <= ALLOWED_AXIOMS,
             "Lean theorem has unexpected axioms: " + name + " " +
             ", ".join(sorted(dependencies - ALLOWED_AXIOMS)))
    return dict(
        file=str(SOURCE.relative_to(ROOT)),
        sha256=sha(source_bytes),
        compiler=str(LEAN.relative_to(ROOT)),
        compiler_sha256=sha(LEAN.read_bytes()),
        status="kernel-checked",
        theorems=list(THEOREMS),
        claim_scope="explicit stack-reservation transition model; no OS signal theorem",
    )


def checked_recursion_candidate(index):
    metadata, raw = index.read("scp", "funs", 32195)
    need(metadata["sha256"] == ALIAS_SHA and sha(raw) == ALIAS_SHA,
         "Pinned generated alias row changed")
    with tempfile.TemporaryDirectory(prefix="scp-lean-recursion-") as directory:
        response = run_checked([
            sys.executable, str(SCANNER), "--directory", directory,
            "--target", "scp", "--ordinal", "32195"
        ])
    lines = [json.loads(line) for line in response.stdout.splitlines()]
    need(len(lines) == 2 and lines[0]["sha256"] == ALIAS_SHA,
         "Lean recursion scanner did not return the pinned alias row")
    calls = lines[0]["candidates"]
    need(len(calls) == 1 and calls[0]["kind"] == "direct-self-call",
         "Pinned alias self-call candidate changed")
    address = calls[0]["address"]
    site = _core_site_identity(index.archive.manifest_sha256, "scp",
                               "funs", 32195, ALIAS_SHA, address)
    need(site["sha256"] == ALIAS_SITE_SHA,
         "Pinned alias self-call site identity changed")
    return dict(
        row_ordinal=32195,
        row_sha256=ALIAS_SHA,
        site_identity=site,
        inherited_location=calls[0]["location"],
        location_origin=calls[0]["location_origin"],
        checker_source=str((SCANNER.parent / "Main.lean").relative_to(ROOT)),
        checker_sha256=sha((SCANNER.parent / "Main.lean").read_bytes()),
        theorem="RecursionSearch.selfCalls_sound",
        claim_scope="typed archived self-call occurrence and symbol-key match",
    )


def checked_native(index):
    c_bytes = C_SOURCE.read_bytes()
    elf = BINARY.read_bytes()
    need(sha(c_bytes) == C_SHA and sha(elf) == ELF_SHA,
         "Pinned C source or ELF changed")
    soft, _ = resource.getrlimit(resource.RLIMIT_STACK)
    need(soft == 8192 * 1024, "Observed process stack soft limit changed")
    need(c_bytes.decode().splitlines()[1864].strip() == "sink(1, vect, src);",
         "Pinned original C recursion edge changed")
    prologue = []
    for offset, expected, reservation in (FIRST_SUB, SECOND_SUB):
        need(elf[offset:offset + len(expected)] == expected,
             "Pinned sink prologue instruction bytes changed")
        prologue.append(dict(file_offset=hex(offset), bytes_hex=expected.hex(),
                             reservation_bytes=reservation))
    profile_bytes = PROFILE.read_bytes()
    profile = json.loads(profile_bytes)
    need(profile["target"] == "scp" and profile["expect_signal"] == "SIGSEGV",
         "Native depth profile target or outcome changed")
    need(base64.b64decode(profile["record_base64"], validate=True) == RECORD,
         "Native depth profile record differs from Lean witness bytes")
    need(profile["core_link"]["core_site_sha256"] == NAMED_SITE_SHA,
         "Profile C/Core site changed")
    need(profile["core_link"]["source_sha256"] == C_SHA
         and profile["core_link"]["source_line"] == 1865,
         "Profile original C source identity changed")

    receipt_bytes = RECEIPT.read_bytes()
    receipt = json.loads(receipt_bytes)
    need(receipt["id"] == RECEIPT.parent.name
         and receipt["binary"]["sha256"] == ELF_SHA,
         "Native receipt identity changed")
    need(receipt["source_identity"]["archive_manifest_sha256"]
         == index.archive.manifest_sha256,
         "Native receipt belongs to a different archive")
    need(base64.b64decode(receipt["recipe"]["stdin_base64"], validate=True)
         == RECORD * DEPTH,
         "Native receipt input differs from the Lean witness")
    need(receipt["recipe"]["argv"][:2] == ["-r", "-t"]
         and receipt["recipe"]["expect_signal"] == "SIGSEGV",
         "Native receipt invocation differs")
    need(receipt["observation"]["expected_observed"] is True
         and receipt["observation"]["primary_site"]["signal"] == "SIGSEGV",
         "Native receipt does not record a fatal SIGSEGV")
    run_checked([
        sys.executable, str(ROOT / "search/native_signal_replay.py"),
        "verify", str(RECEIPT), "--sha256", sha(receipt_bytes)
    ], timeout=120)

    catalog_response = run_checked([
        sys.executable, str(ROOT / "search/signal_catalog.py"),
        "native-reproducer", CATALOG_REPRODUCER_ID
    ], timeout=120)
    catalog = json.loads(catalog_response.stdout)
    need(catalog["id"] == CATALOG_REPRODUCER_ID
         and catalog["target"] == "scp"
         and catalog["native"]["signal"] == "SIGSEGV",
         "Catalog reproducer identity or signal changed")
    need(catalog["native"]["observation_id"] == receipt["id"]
         and catalog["native"]["receipt_sha256"] == sha(receipt_bytes),
         "Catalog reproducer points to a different native receipt")
    need(catalog["native"]["stdin"] ==
         dict(bytes=len(RECORD) * DEPTH, sha256=sha(RECORD * DEPTH)),
         "Catalog reproducer points to different input bytes")
    need(catalog["search"]["witness_depth"] == DEPTH
         and catalog["search"]["profile_sha256"] == sha(profile_bytes),
         "Catalog search result or profile changed")
    need(catalog["assets"]["profile"]["sha256"] == sha(profile_bytes)
         and catalog["assets"]["script"]["sha256"] == CATALOG_SCRIPT_SHA,
         "Catalog-owned input profile or generated program changed")
    need(catalog["formal"]["archived_core_candidate"]["sha256"]
         == NAMED_SITE_SHA
         and catalog["formal"]["exact_cabs_original_c_expression_verified"]
         and catalog["formal"]["core_own_ancestor_cabs_region_verified"],
         "Catalog Cabs/Core evidence changed")
    expression = catalog["original_c"]
    span = expression["byte_span"]
    text = c_bytes[span["start"]:span["end"]]
    need(sha(text) == expression["expression_sha256"]
         and text.decode() == expression["text"]
         and expression["line"] == 1865,
         "Catalog exact original-C expression changed")
    script_path = Path(catalog["assets"]["script"]["path"]).resolve()
    need(script_path.is_file() and script_path.is_relative_to(ROOT)
         and sha(script_path.read_bytes()) == CATALOG_SCRIPT_SHA,
         "Catalog-owned generated Bash program changed")
    replay = catalog["replay"]
    need(replay["command"] == ["/usr/bin/bash", str(script_path)]
         and sha(Path(replay["command"][0]).read_bytes())
         == replay["bash_sha256"],
         "Catalog replay command or Bash binary changed")
    run_checked(["/usr/bin/bash", "-n", str(script_path)])
    observed = run_checked(replay["command"], timeout=90)
    need(replay["success_marker"] in observed.stdout,
         "Generated Bash program did not verify a native SIGSEGV")
    reproducer = dict(
        catalog_id=CATALOG_REPRODUCER_ID,
        path=str(script_path.relative_to(ROOT)),
        sha256=CATALOG_SCRIPT_SHA,
        profile_sha256=sha(profile_bytes),
        search_result_sha256=catalog["search"]["result_sha256"],
        receipt_id=receipt["id"],
        input_sha256=sha(RECORD * DEPTH),
        exact_cabs_call_witness_id=catalog["formal"]
            ["exact_cabs_call_witness_id"],
        core_cabs_bridge_id=catalog["formal"]["core_cabs_bridge_id"],
        replay_verified=True,
    )

    return dict(
        original_c=dict(path=str(C_SOURCE.relative_to(ROOT)),
                        sha256=C_SHA, recursive_call_line=1865),
        pinned_elf=dict(path=str(BINARY.relative_to(ROOT)), sha256=ELF_SHA,
                        observed_sink_prologue=prologue,
                        reservation_bytes_per_entered_sink=4488,
                        observed_soft_stack_limit_bytes=soft),
        depth_profile=dict(path=str(PROFILE.relative_to(ROOT)),
                           sha256=sha(profile_bytes)),
        reproducer=reproducer,
        input=dict(record_base64=base64.b64encode(RECORD).decode(),
                   record_count=DEPTH, byte_count=len(RECORD) * DEPTH,
                   sha256=sha(RECORD * DEPTH)),
        native_receipt=dict(id=receipt["id"],
                            path=str(RECEIPT.relative_to(ROOT)),
                            sha256=sha(receipt_bytes),
                            primary_site_key=receipt["observation"]
                                ["primary_site"]["stable_site_key"]),
    )


def build():
    proof = checked_lean()
    index = Index()
    try:
        candidate = checked_recursion_candidate(index)
        native = checked_native(index)
        manifest = index.archive.manifest_sha256
    finally:
        index.db.close()
    need(native["input"]["byte_count"] == 20480,
         "Lean input length theorem no longer matches witness")
    payload = dict(
        schema=1,
        kind="scp-stack-reservation-proof-obligation",
        archive_manifest_sha256=manifest,
        model_target="scp",
        formal=proof,
        typed_recursion_candidate=candidate,
        named_sink_core_site_sha256=NAMED_SITE_SHA,
        witness=native,
        unproved_premises=[
            dict(key="source_correspondence",
                 statement="The checked original-C expression and Cabs/Core annotated ancestor are semantically preserved by translation into the selected archived alias and named sink call."),
            dict(key="protocol_to_recursion",
                 statement="Each accepted nested directory record reaches another sink entry unless execution has already faulted."),
            dict(key="compiler_stack_semantics",
                 statement="The hash-pinned x86-64 prologue bytes decode as two stack reservations totaling at least 4488 bytes on each entered sink call, with no intervening release before recursion."),
            dict(key="stack_budget",
                 statement="The available process stack at this invocation is at most the observed 8192 KiB soft limit."),
            dict(key="native_signal_bridge",
                 statement="Exhausting this process stack through the pinned code and platform behavior produces the recorded fatal SIGSEGV."),
        ],
        conclusion_scope="Lean proves abstract reservation failure; the native receipt separately demonstrates SIGSEGV for the exact input.",
    )
    payload["id"] = sha(json.dumps(payload, sort_keys=True,
                                   separators=(",", ":")).encode())
    return payload


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--verify", type=Path,
                        help="Recheck a saved obligation against current pinned evidence")
    args = parser.parse_args()
    payload = build()
    encoded = (json.dumps(payload, sort_keys=True, indent=2) + chr(10)).encode()
    if args.verify is not None:
        path = args.verify.resolve()
        need(path.name == payload["id"] + ".json"
             and path.read_bytes() == encoded,
             "Saved obligation differs from the checked current evidence")
        status = "verified"
    else:
        destination = args.output_dir.resolve()
        destination.mkdir(parents=True, exist_ok=True)
        path = destination / (payload["id"] + ".json")
        if path.exists():
            need(path.read_bytes() == encoded,
                 "Existing obligation ID has changed bytes")
        else:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            with os.fdopen(fd, "wb") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
        status = "checked"
    print(json.dumps(dict(status=status, id=payload["id"],
                          path=str(path), sha256=sha(encoded)), sort_keys=True))


if __name__ == "__main__":
    main()
