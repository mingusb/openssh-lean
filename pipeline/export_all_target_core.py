#!/usr/bin/env python3
"""Export full linked Core records for every configured OpenSSH native target.

Targets run under one checked lease. A successful export means checked input
bytes yielded a closed linked Core record; it is not a C/Lean equivalence proof.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import hashlib
import gzip
import json
import os
from pathlib import Path
import re
import shutil
from statistics import median
import subprocess
import sys
import time
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = Path(__file__).resolve().parents[1] / "local/runtime"
sys.path.insert(0, str(ROOT / "work"))
import build_guard
from export_linked_core import delegated_scope, export_argv
from core_export_identity import semantic_key
from run_pointer_check_plan import check_build


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def checked(path, expected, label):
    require(Path(path).is_file() and sha(path) == expected,
            f"{label} changed: {path}")


def load_bindings(receipt_path, selected):
    report = json.loads(receipt_path.read_bytes())
    target_receipt = report["scope"] == "all-configured-target-input-bindings"
    census_receipt = report["scope"] == "all-pinned-census-unit-input-bindings"
    require((target_receipt or census_receipt) and
            report["schema_version"] == 1, "Wrong source binding receipt")
    checked(report["manifest_path"], report["manifest_sha256"], "Target manifest")
    checked(report["shared_libc_binding_path"],
            report["shared_libc_binding_sha256"], "Shared libc binding")
    checked(report["import_report_path"], report["import_report_sha256"],
            "Cabs import report")
    rows = report["targets"]
    require(rows and len(rows) == len({row["target"] for row in rows}),
            "Missing or duplicate target binding")
    if census_receipt:
        require(len(rows) == report["census_unit_count"] and
                len({row["source"] for row in rows}) == len(rows) and
                all(row["linked_units"] == 1 for row in rows),
                "Census receipt omits or duplicates source units")
    if selected:
        require(selected in {row["target"] for row in rows},
                f"Unconfigured target: {selected}")
        rows = [row for row in rows if row["target"] == selected]
    bindings = []
    for row in rows:
        require(re.fullmatch(r"[A-Za-z0-9_.+-]+", row["target"]),
                "Unsafe target name")
        path = Path(row["path"]).resolve(strict=True)
        require(path.parent == receipt_path.parent and
                path.name == row["target"] + ".json",
                "Binding is outside its checked receipt directory")
        checked(path, row["sha256"], "Target binding")
        binding = json.loads(path.read_bytes())
        expected_scope = ("configured-openssh-target-link-input-provenance" if
                          target_receipt else
                          "pinned-openssh-census-unit-input-provenance")
        expected_mode = ("target-inputs-only" if target_receipt else
                         "census-unit-input-only")
        require(binding["scope"] == expected_scope and
                binding["schema_version"] == 2 and
                binding["target"] == row["target"] and
                binding["receipt_mode"] == expected_mode and
                binding["input_provenance_verified"] is True and
                binding["linked_core_certified"] is False and
                binding["lean_argv_executed"] is False and
                len(binding["frontend_order"]) == row["linked_units"] > 0 and
                len({item["source"] for item in binding["frontend_order"]}) ==
                row["linked_units"] and
                (target_receipt or row["linked_units"] == 1 and
                 binding["frontend_order"][0]["source"] == row["source"]) and
                binding["core_link_order"] ==
                list(range(row["linked_units"] - 1, -1, -1)) + ["libc"],
                f"{row['target']}: malformed source binding")
        checked(binding["target_manifest_path"],
                binding["target_manifest_sha256"], "Target manifest")
        if target_receipt:
            checked(binding["target_link_map_path"],
                    binding["target_link_map_sha256"], "Target link map")
            checked(binding["native_target"]["path"],
                    binding["native_target"]["sha256"], "Native target")
        else:
            obj = binding["compiled_object"]
            checked(obj["object_path"], obj["object_sha256"],
                    "Census compiled object")
            require(obj["source"] == row["source"] and
                    binding["source_class"] == row["source_class"],
                    "Census object and binding source differ")
            if binding["source_class"] == "archive-only":
                member = binding["archive_member"]
                checked(member["archive_path"], member["archive_sha256"],
                        "Native archive")
                require(member["object_path"] == obj["object_path"] and
                        member["object_sha256"] == obj["object_sha256"] and
                        member["source"] == obj["source"],
                        "Archive member and compiled object differ")
            else:
                require(binding["source_class"] == "configured-executable-link",
                        "Unknown census source class")
        checked(binding["build_receipt_path"],
                binding["build_receipt_sha256"], "Build receipt")
        checked(binding["translator"]["path"],
                binding["translator"]["sha256"], "Translator")
        checked(binding["binding_generator_path"],
                binding["binding_generator_sha256"], "Binding generator")
        for source in binding["frontend_order"]:
            checked(source["original_path"], source["original_sha256"],
                    "Original C source")
            checked(source["preprocessed_path"],
                    source["preprocessed_sha256"], "Preprocessed C source")
            checked(source["cabs_path"], source["cabs_sha256"], "Cabs input")
        bindings.append((path, binding))
    return bindings


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n",
                         encoding="utf-8")
    temporary.replace(path)


def read_resource_timing(path):
    if not path.is_file():
        return {}
    wanted = {
        "User time (seconds)": "user_cpu_seconds",
        "System time (seconds)": "system_cpu_seconds",
        "Percent of CPU this job got": "cpu_percent",
        "Maximum resident set size (kbytes)": "peak_rss_kib",
        "Major (requiring I/O) page faults": "major_faults",
        "Minor (reclaiming a frame) page faults": "minor_faults",
        "File system inputs": "filesystem_inputs",
        "File system outputs": "filesystem_outputs",
        "Voluntary context switches": "voluntary_context_switches",
        "Involuntary context switches": "involuntary_context_switches",
    }
    result = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        for label, key in wanted.items():
            if line.lstrip().startswith(label + ":"):
                value = line.split(":", 1)[1].strip()
                result[key] = value
                break
    return result


def export_one(path, binding, folder, mode):
    target = binding["target"]
    suffix = "model-core" if mode == "core-data" else "linked-core"
    raw_output = folder / (target + f".{suffix}.json")
    output = folder / (target + f".{suffix}.json.gz")
    run_dir = folder / (target + ".run")
    run_dir.mkdir()
    receipt_path = folder / (target + ".receipt.json")
    command = export_argv(path, raw_output, binding, runnable=mode == "core-data")
    resource_path = run_dir / "resource.txt"
    timed_command = ["/usr/bin/time", "-v", "-o", str(resource_path), *command]
    start = time.monotonic()
    phases = {}
    timeline = []
    detail = {"translation_units": {}, "fields": {}, "operations": {}}
    report = {
        "terminal": False, "passed": False,
        "artifact_format": mode,
        "scope": ("linked Core model data of one configured OpenSSH target" if
                  mode == "core-data" else
                  "full linked Core record of one configured OpenSSH target" if
                  binding["receipt_mode"] == "target-inputs-only" else
                  "single census unit and libc Core record"),
        "target": target, "linked_unit_count": len(binding["frontend_order"]),
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "binding_path": str(path), "binding_sha256": sha(path),
        "artifact_binding_path": str(path),
        "artifact_binding_sha256": sha(path),
        "semantic_key": semantic_key(binding),
        "translator_sha256": binding["translator"]["sha256"],
        "argv": command, "supervised_argv": timed_command,
        "output": str(output),
    }
    write_json(receipt_path, report)
    print(json.dumps({"stage": "start", "target": target}), flush=True)
    scope = None
    try:
        with (run_dir / "stdout.log").open("wb") as stdout, \
             (run_dir / "stderr.log").open("wb") as stderr, \
             (run_dir / "timing-events.jsonl").open("w", encoding="utf-8") as timing_events:
            from process_scope import ProcessScope
            scope = ProcessScope(run_dir / "process")
            proc = scope.start(timed_command, cwd=ROOT,
                               env=dict(os.environ, LEAN_ABORT_ON_PANIC="1"),
                               stdout=stdout, stderr=subprocess.PIPE)
            assert proc.stderr is not None
            for raw in proc.stderr:
                stderr.write(raw)
                stderr.flush()
                line = raw.decode("utf-8", errors="replace").strip()
                elapsed = round(time.monotonic() - start, 3)
                stage = None
                prefix = "cerberus-lean: linked Core timing "
                if line.startswith(prefix):
                    values = dict(item.split("=", 1) for item in
                                  line[len(prefix):].split() if "=" in item)
                    event = {"elapsed_seconds": elapsed, **values}
                    timing_events.write(json.dumps(event, sort_keys=True) + "\n")
                    timing_events.flush()
                    kind = values.get("kind")
                    if kind == "tu":
                        key = values.get("source", values.get("index", "?"))
                        row = detail["translation_units"].setdefault(key, {
                            "source": values.get("source"),
                            "index": values.get("index"),
                            "phases_ns": {}})
                        row["phases_ns"][values.get("phase", "?")] = int(values.get("ns", "0"))
                        if values.get("phase") == "total":
                            stage = "tu_complete"
                    elif kind == "item":
                        field = values.get("field", "?")
                        row = detail["fields"].setdefault(field, {
                            "item_count": 0, "slowest_item_ns": 0})
                        row["item_count"] += 1
                        ns = int(values.get("ns", "0"))
                        if ns > row["slowest_item_ns"]:
                            row["slowest_item_ns"] = ns
                            row["slowest_ordinal"] = int(values.get("ordinal", "-1"))
                    elif kind == "field":
                        field = values.get("field", "?")
                        row = detail["fields"].setdefault(field, {
                            "item_count": 0, "slowest_item_ns": 0})
                        row["total_ns"] = int(values.get("ns", "0"))
                        row["declared_entries"] = int(values.get("entries", "0"))
                        stage = "field_complete"
                    elif kind == "operation":
                        name = values.get("name", "?")
                        ns = int(values.get("ns", "0"))
                        row = detail["operations"].setdefault(name, {
                            "count": 0, "total_ns": 0, "max_ns": 0})
                        row["count"] += 1
                        row["total_ns"] += ns
                        row["max_ns"] = max(row["max_ns"], ns)
                        if name not in {"verify_file", "verify_digest"}:
                            stage = "operation_complete"
                elif "linked export runtime and libc prepared" in line:
                    stage = "libc_ready"
                    phases[stage] = elapsed
                elif "linked body export translated " in line:
                    found = re.search(r"translated (\d+)/(\d+) inputs", line)
                    if found:
                        done, total = map(int, found.groups())
                        stage = "translation_progress"
                        if done == total:
                            phases["translation_done"] = elapsed
                        phases["translation_done_count"] = done
                        phases["translation_total_count"] = total
                elif "full linked Core export linking " in line:
                    stage = "link_start"
                    phases[stage] = elapsed
                elif "full Core link " in line:
                    found = re.search(
                        r"full Core link (\d+)/(\d+) step_ms=(\d+) elapsed_ms=(\d+)",
                        line)
                    if found:
                        done, total, step_ms, cumulative_ms = map(int, found.groups())
                        stage = "link_progress"
                        phases["link_done_count"] = done
                        phases["link_total_count"] = total
                        phases["last_link_step_ms"] = step_ms
                        phases["max_link_step_ms"] = max(
                            phases.get("max_link_step_ms", 0), step_ms)
                        phases["link_elapsed_ms"] = cumulative_ms
                        if done == total:
                            phases["link_done"] = elapsed
                elif "exporting complete linked Core record data" in line:
                    stage = "snapshot_start"
                    phases[stage] = elapsed
                if stage is not None:
                    event = {"elapsed_seconds": elapsed, "stage": stage, "line": line}
                    timeline.append(event)
                    write_json(run_dir / "stage.json", {
                        "target": target, "current": event,
                        "phases": phases, "timeline": timeline,
                        "detail": detail,
                    })
            code = proc.wait()
            process_terminal_elapsed = time.monotonic() - start
            residual = scope.finish()
        phase_seconds = {}
        for label, start_key, end_key in [
            ("libc_preparation", None, "libc_ready"),
            ("translation", "libc_ready", "translation_done"),
            ("link", "link_start", "link_done"),
            ("snapshot", "snapshot_start", None),
        ]:
            first = phases.get(start_key, 0) if start_key else 0
            last = phases.get(end_key, process_terminal_elapsed) if end_key else process_terminal_elapsed
            if (not start_key or start_key in phases) and (not end_key or end_key in phases):
                phase_seconds[label] = round(last - first, 3)
        link_steps = [int(match.group(1))
                      for event in timeline
                      if (match := re.search(r"step_ms=(\d+)", event["line"]))]
        translate_events = [event["elapsed_seconds"] for event in timeline
                            if event["stage"] == "translation_progress"]
        if link_steps:
            phases["median_link_step_ms"] = median(link_steps)
        if len(translate_events) > 1:
            phases["max_translation_batch_seconds"] = round(
                max(b - a for a, b in zip(translate_events, translate_events[1:])), 3)
        raw_hash_start = time.monotonic()
        raw_sha = sha(raw_output) if raw_output.is_file() else None
        raw_hash_seconds = round(time.monotonic() - raw_hash_start, 3)
        raw_bytes = raw_output.stat().st_size if raw_output.is_file() else None
        compression_seconds = None
        compression_verify_seconds = None
        if code == 0 and not residual and raw_sha is not None:
            compression_start = time.monotonic()
            temporary = Path(str(output) + ".tmp")
            with raw_output.open("rb") as source, temporary.open("wb") as destination:
                with gzip.GzipFile(filename="", mode="wb", fileobj=destination,
                                   compresslevel=1, mtime=0) as compressed:
                    shutil.copyfileobj(source, compressed, length=1024 * 1024)
            compression_seconds = round(time.monotonic() - compression_start, 3)
            verify_start = time.monotonic()
            decompressed_hash = hashlib.sha256()
            with gzip.open(temporary, "rb") as restored:
                for block in iter(lambda: restored.read(1024 * 1024), b""):
                    decompressed_hash.update(block)
            if decompressed_hash.hexdigest() != raw_sha:
                raise RuntimeError("Compressed Core snapshot differs from generated JSON")
            temporary.replace(output)
            raw_output.unlink()
            compression_verify_seconds = round(time.monotonic() - verify_start, 3)
        output_hash_start = time.monotonic()
        output_sha = sha(output) if output.is_file() else None
        output_hash_seconds = round(time.monotonic() - output_hash_start, 3)
        report.update(terminal=True, exit_code=code,
                      residual_processes=residual,
                      encoding="gzip+json" if output.is_file() else None,
                      raw_output_sha256=raw_sha, raw_output_bytes=raw_bytes,
                      compression_seconds=compression_seconds,
                      compression_verify_seconds=compression_verify_seconds,
                      raw_hash_seconds=raw_hash_seconds,
                      output_hash_seconds=output_hash_seconds,
                      output_present=output.is_file(),
                      output_sha256=output_sha,
                      output_bytes=output.stat().st_size if output.is_file() else None,
                      passed=code == 0 and not residual and output.is_file() and
                      sha(path) == report["binding_sha256"] and
                      sha(binding["translator"]["path"]) ==
                      binding["translator"]["sha256"],
                      timing={"total_seconds": round(time.monotonic() - start, 3),
                              "resource": read_resource_timing(resource_path),
                              "milestones_seconds": phases,
                              "phase_seconds": phase_seconds,
                              "events": timeline,
                              "detail": detail,
                              "timing_events_path": str(run_dir / "timing-events.jsonl")})
    except BaseException as exc:
        if scope is not None:
            scope.finish(cancel=True)
        report.update(terminal=True, error=str(exc),
                      timing={"total_seconds": round(time.monotonic() - start, 3),
                              "resource": read_resource_timing(resource_path),
                              "milestones_seconds": phases,
                              "events": timeline,
                              "detail": detail,
                              "timing_events_path": str(run_dir / "timing-events.jsonl")})
    finally:
        write_json(receipt_path, report)
    print(json.dumps({"stage": "terminal", "target": target,
                      "passed": report["passed"],
                      "seconds": report["timing"]["total_seconds"],
                      "receipt": str(receipt_path)}), flush=True)
    return report

def timing_table(results):
    def number(value):
        return "-" if value is None else str(value)
    lines = [
        "| Target | TUs | Prepare s | Translate s | Link s | Quote s | Total s | CPU s | Peak GiB | Slowest 5 TUs s | Max link step ms | Slowest Core entry | Entry ms |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |",
    ]
    for row in sorted(results, key=lambda item: item["target"]):
        timing = row.get("timing", {})
        phase = timing.get("phase_seconds", {})
        milestones = timing.get("milestones_seconds", {})
        resource = timing.get("resource", {})
        cpu = None
        if "user_cpu_seconds" in resource and "system_cpu_seconds" in resource:
            cpu = round(float(resource["user_cpu_seconds"]) +
                        float(resource["system_cpu_seconds"]), 3)
        peak = round(int(resource["peak_rss_kib"]) / (1024 * 1024), 3) if "peak_rss_kib" in resource else None
        fields = timing.get("detail", {}).get("fields", {})
        slowest = max(fields.items(), key=lambda item: item[1].get("slowest_item_ns", 0),
                      default=None)
        slowest_name = "-"
        slowest_ms = None
        if slowest is not None and slowest[1].get("slowest_item_ns", 0) > 0:
            slowest_name = f"{slowest[0]}[{slowest[1].get('slowest_ordinal', '?')}]"
            slowest_ms = round(slowest[1]["slowest_item_ns"] / 1_000_000, 3)
        cells = [
            row["target"], number(row.get("linked_unit_count")),
            number(phase.get("libc_preparation")), number(phase.get("translation")),
            number(phase.get("link")), number(phase.get("snapshot")),
            number(timing.get("total_seconds")), number(cpu), number(peak),
            number(milestones.get("max_translation_batch_seconds")),
            number(milestones.get("max_link_step_ms")),
            slowest_name, number(slowest_ms),
        ]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def reusable_candidates(bindings, mode):
    """Find matching prior artifacts, retaining their original source binding."""
    current = {binding["target"]: semantic_key(binding)
               for _, binding in bindings}
    candidates = {}
    history = sorted(
        set(RUNTIME.glob("release-unit-core-*/result.json")) |
        set(RUNTIME.glob("release-core-*/result.json")) |
        set(RUNTIME.glob("release-runnable-core-*/result.json")) |
        set(RUNTIME.glob("release-*core-*/*.receipt.json")),
        key=lambda path: path.stat().st_mtime, reverse=True)
    for result_path in history:
        try:
            report_bytes = result_path.read_bytes()
            report = json.loads(report_bytes)
            report_sha256 = hashlib.sha256(report_bytes).hexdigest()
            if not (report.get("terminal") and report.get("passed")):
                continue
            if report.get("artifact_format", "proof") != mode:
                continue
            rows = report.get("targets", [report])
            for row in rows:
                if row.get("artifact_format", "proof") != mode:
                    continue
                target = row["target"]
                if target not in current or target in candidates or not row["passed"]:
                    continue
                artifact_binding_path = Path(
                    row.get("artifact_binding_path", row["binding_path"]))
                artifact_binding_sha256 = row.get(
                    "artifact_binding_sha256", row["binding_sha256"])
                if not artifact_binding_path.is_file() or (
                        sha(artifact_binding_path) != artifact_binding_sha256):
                    continue
                prior_binding = json.loads(artifact_binding_path.read_bytes())
                if semantic_key(prior_binding) == current[target]:
                    candidates[target] = (result_path, report_sha256, row,
                                          artifact_binding_path,
                                          artifact_binding_sha256)
        except (KeyError, TypeError, ValueError, OSError,
                json.JSONDecodeError):
            continue
        if len(candidates) == len(bindings):
            break
    return candidates


def reuse_or_export(path, binding, folder, candidate, mode):
    if candidate is None:
        return export_one(path, binding, folder, mode)
    started = time.monotonic()
    (prior_result_path, prior_result_sha, prior, artifact_binding_path,
     artifact_binding_sha) = candidate
    source = Path(prior["output"])
    if not source.is_file() or sha(source) != prior["output_sha256"]:
        raise RuntimeError(f"Cached Core artifact changed: {source}")
    if sha(artifact_binding_path) != artifact_binding_sha or (
            semantic_key(json.loads(artifact_binding_path.read_bytes())) !=
            semantic_key(binding)):
        raise RuntimeError(f"Cached Core binding changed: {artifact_binding_path}")
    result = {
        "terminal": True, "passed": True,
        "artifact_format": mode,
        "scope": prior["scope"], "target": binding["target"],
        "linked_unit_count": len(binding["frontend_order"]),
        "binding_path": str(path), "binding_sha256": sha(path),
        "artifact_binding_path": str(artifact_binding_path),
        "artifact_binding_sha256": artifact_binding_sha,
        "semantic_key": semantic_key(binding),
        "translator_sha256": binding["translator"]["sha256"],
        "output": str(source), "output_sha256": prior["output_sha256"],
        "output_bytes": prior["output_bytes"],
        "raw_output_sha256": prior.get("raw_output_sha256"),
        "raw_output_bytes": prior.get("raw_output_bytes"),
        "output_present": True, "encoding": prior.get("encoding", "json"),
        "reused_from_result_path": str(prior_result_path),
        "reused_from_result_sha256": prior_result_sha,
        "timing": {"total_seconds": round(time.monotonic() - started, 3),
                   "cache_reuse": True},
    }
    write_json(folder / (binding["target"] + ".receipt.json"), result)
    print(json.dumps({"stage": "terminal", "target": binding["target"],
                      "passed": True, "reused": True,
                      "seconds": result["timing"]["total_seconds"]}), flush=True)
    return result


def scheduling_history(bindings):
    """Prior timings affect dispatch only; they never certify an output."""
    history = sorted(RUNTIME.glob("release-unit-core-*/result.json"),
                     key=lambda path: path.stat().st_mtime, reverse=True)
    for path in history:
        try:
            report = json.loads(path.read_bytes())
            if not (report.get("terminal") and report.get("passed") and
                    report.get("target_count") == len(bindings)):
                continue
            rows = {row["target"]: row for row in report["targets"]}
            if set(rows) != {binding["target"] for _, binding in bindings}:
                continue
            estimates = {}
            for target, row in rows.items():
                resource = row.get("timing", {}).get("resource", {})
                estimates[target] = {
                    "seconds": float(row["timing"]["total_seconds"]),
                    "rss_bytes": int(resource["peak_rss_kib"]) * 1024,
                }
            return str(path), estimates
        except (KeyError, TypeError, ValueError, OSError, json.JSONDecodeError):
            continue
    return None, {}


def memory_budget():
    values = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        if line.startswith(("MemTotal:", "MemAvailable:")):
            name, amount, _ = line.split()
            values[name[:-1]] = int(amount) * 1024
    if not {"MemTotal", "MemAvailable"} <= values.keys():
        raise RuntimeError("Cannot observe available Linux memory for export scheduling")
    # Dispatch headroom prevents observed large workers from paging together.
    # This is not a process, address-space, cgroup, or swap memory limit.
    return min(values["MemAvailable"], values["MemTotal"] * 4 // 5)


def dispatch_order(bindings, estimates):
    return sorted(bindings, key=lambda pair:
                  (-estimates.get(pair[1]["target"], {}).get("seconds", 0),
                   pair[1]["target"]))


def estimated_rss(binding, estimates, budget):
    observed = estimates.get(binding["target"], {}).get("rss_bytes")
    return max(1, observed) if observed is not None else max(1, budget // 6)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bindings", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--target", default=None)
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument("--format", choices=("proof", "core-data"), default="proof")
    args = parser.parse_args()
    require(args.jobs >= 1, "Jobs must be positive")
    if not delegated_scope():
        os.execvp("systemd-run", ["systemd-run", "--user", "--scope",
                  sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]])
    receipt_path = args.bindings.resolve(strict=True)
    output = args.output_dir.absolute()
    require(receipt_path.is_relative_to(RUNTIME) and
            output.parent == RUNTIME and not output.is_symlink(),
            "Use a direct runtime output directory")
    started = time.monotonic()
    with build_guard.workflow_lock():
        build_guard.verify_tools()
        build_receipt = RUNTIME / "logs/whole-table-build.json"
        check_build(ROOT, RUNTIME, sha(build_receipt))
        bindings = load_bindings(receipt_path, args.target)
        require(all(row["build_receipt_sha256"] == sha(build_receipt)
                    for _, row in bindings),
                "Target binding does not match checked build")
        prepared_seconds = round(time.monotonic() - started, 3)
        if output.exists():
            summary_path = output / "result.json"
            require(summary_path.is_file(), "Existing output has no terminal result")
            summary = json.loads(summary_path.read_bytes())
            require(summary.get("terminal") and summary.get("passed") and
                    summary.get("artifact_format", "proof") == args.format and
                    summary.get("binding_receipt_sha256") == sha(receipt_path) and
                    summary.get("target_count") == len(bindings),
                    "Existing output is not the requested completed run")
            by_target = {row["target"]: row for row in summary["targets"]}
            require(set(by_target) == {row["target"] for _, row in bindings},
                    "Existing output has a different target inventory")
            for path, binding in bindings:
                row = by_target[binding["target"]]
                checked(row["output"], row["output_sha256"],
                        "Existing Core output")
                require(row["passed"] and row["semantic_key"] ==
                        semantic_key(binding) and
                        row.get("artifact_format", "proof") == args.format,
                        "Existing output differs from requested inputs")
            print(json.dumps({"passed": True, "reused": True,
                              "target_count": len(bindings),
                              "result": str(summary_path)}), flush=True)
            return 0
        output.mkdir()
        results = []
        history_path, estimates = scheduling_history(bindings)
        candidates = reusable_candidates(bindings, args.format)
        budget = memory_budget()
        queue = dispatch_order(bindings, estimates)
        max_workers = min(args.jobs, len(bindings))
        schedule = {"history_receipt": history_path,
                    "cache_candidate_count": len(candidates),
                    "memory_dispatch_budget_bytes": budget,
                    "max_workers": max_workers, "starts": []}
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            active = {}
            active_rss = 0
            while queue or active:
                while queue and len(active) < max_workers:
                    chosen = next((i for i, (_, row) in enumerate(queue)
                                   if active_rss + estimated_rss(row, estimates,
                                                                  budget) <= budget),
                                  None)
                    if chosen is None:
                        if active:
                            break
                        chosen = 0  # An oversized unit must still make progress.
                    path, binding = queue.pop(chosen)
                    estimate = estimated_rss(binding, estimates, budget)
                    future = pool.submit(reuse_or_export, path, binding, output,
                                         candidates.get(binding["target"]), args.format)
                    active[future] = (binding["target"], estimate)
                    active_rss += estimate
                    schedule["starts"].append({"target": binding["target"],
                        "estimated_rss_bytes": estimate})
                if active:
                    finished, _ = wait(active, return_when=FIRST_COMPLETED)
                    for future in finished:
                        _, estimate = active.pop(future)
                        active_rss -= estimate
                        results.append(future.result())
        for prior_path, prior_sha in {
                str(row["reused_from_result_path"]): row["reused_from_result_sha256"]
                for row in results if "reused_from_result_path" in row}.items():
            require(sha(prior_path) == prior_sha,
                    f"Cached Core receipt changed during export: {prior_path}")
        write_json(output / "schedule.json", schedule)
        passed = all(row["passed"] for row in results)
        receipt_scope = json.loads(receipt_path.read_bytes())["scope"]
        summary_scope = (
            "configured OpenSSH native target linked-Core snapshots" if
            receipt_scope == "all-configured-target-input-bindings" else
            "all OpenSSH census unit Core snapshots")
        summary = {
            "terminal": True, "passed": passed,
            "artifact_format": args.format,
            "scope": summary_scope,
            "binding_receipt_path": str(receipt_path),
            "binding_receipt_sha256": sha(receipt_path),
            "build_receipt_sha256": sha(build_receipt),
            "target_count": len(bindings),
            "passed_count": sum(row["passed"] for row in results),
            "targets": sorted(results, key=lambda row: row["target"]),
            "behavioral_equivalence_proved": False,
            "timing": {"preparation_seconds": prepared_seconds,
                       "total_seconds": round(time.monotonic() - started, 3)},
        }
        summary_path = output / "result.json"
        summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n",
                                encoding="utf-8")
        (output / "timings.md").write_text(timing_table(results), encoding="utf-8")
        print(json.dumps({"passed": passed, "target_count": len(bindings),
                          "passed_count": summary["passed_count"],
                          "result": str(summary_path)}), flush=True)
        return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
