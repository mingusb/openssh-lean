#!/usr/bin/env python3
"""Attempt a mechanical Cerberus import of configured, unchanged OpenSSH C.

All failures remain in the report. Parsing, Lean elaboration, execution and
equivalence are distinct statuses. No C bodies or library calls are replaced.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

OPENSSH_PIN = "a8c72b842423f0774f542d3c2197247c3dd28d74"
CERBERUS_PIN = "c4284b08f80c4461f97d179896868106e510327e"


def decode_batch_text(value):
    """Decode CerbEscape.text / OCaml decimal byte escapes, not Python octal."""
    output = bytearray()
    escapes = {'n': 10, 'r': 13, 't': 9, 'b': 8, '"': 34, '\\': 92}
    index = 0
    while index < len(value):
        char = value[index]
        if char != '\\':
            output.extend(char.encode('utf-8'))
            index += 1
        elif index + 1 < len(value) and value[index + 1] in escapes:
            output.append(escapes[value[index + 1]])
            index += 2
        elif (index + 3 < len(value) and
              all('0' <= c <= '9' for c in value[index + 1:index + 4]) and
              int(value[index + 1:index + 4]) <= 255):
            output.append(int(value[index + 1:index + 4]))
            index += 4
        else:
            raise ValueError('Unrecognized batch diagnostic escape at '+str(index))
    return output.decode('utf-8')


def diagnostic_observations(diagnostics, stage):
    """Collect framed errors without silently dropping other failed-run output."""
    messages, additional = [], []
    if stage == 'ocaml':
        # OCaml prints each refusal while recording it, then the complete error
        # on exit. Count the terminal aggregate once; retain original streams.
        final = re.search(r'(?m)^.*?  error: unsupported (.*)', diagnostics)
        if final:
            for item in diagnostics[final.start(1):].strip().splitlines():
                if not item:
                    continue
                if messages and not re.match(r'^(?:.*?:\d+:\d+:: |unknown location: )', item):
                    messages[-1] += '\n' + item
                else:
                    messages.append('UNSUPPORTED: ' + item)
            additional = [line for line in diagnostics[:final.start()].splitlines()
                          if line.strip() and not line.startswith('unsupported: ')]
            return messages, additional
    for line in diagnostics.splitlines():
        match = re.fullmatch(r'Error \{msg: "(.*)"\}', line.strip())
        if match:
            try:
                decoded = decode_batch_text(match[1])
            except (ValueError, UnicodeError):
                messages.append(line.strip())
                continue
            if '; cause: ' in decoded:
                decoded = decoded.split('; cause: ', 1)[1]
            if decoded.startswith('UNSUPPORTED: '):
                # translate_checked joins recorded refusals in encounter order.
                # A continuation without a cursor belongs to the preceding
                # message; literal backslash-n remains literal after decoding.
                frame_messages = []
                for item in decoded[len('UNSUPPORTED: '):].split('\n'):
                    if not item:
                        continue
                    if frame_messages and not re.match(r'^(?:.*?:\d+:\d+:: |unknown location: )', item):
                        frame_messages[-1] += '\n' + item
                    else:
                        frame_messages.append('UNSUPPORTED: ' + item)
                messages.extend(frame_messages)
            else:
                messages.append(decoded)
        elif stage == 'parser' and ': error:' in line:
            messages.append(re.sub(r'^.*?:\d+(?::\d+)?:\s*(?:error:\s*)?', '', line.strip()))
        elif line.strip():
            additional.append(line)
    # If there is no recognized error, the full unknown diagnostic is itself
    # the unresolved reason. Otherwise display auxiliary output separately:
    # a warning beside an error must not become another claimed blocker.
    if not messages and diagnostics.strip():
        return [diagnostics.strip()], []
    return messages, additional


def diagnostic_messages(diagnostics, stage):
    return diagnostic_observations(diagnostics, stage)[0]


def blocker_inventory(report, priority_units):
    groups = {}
    failed_units = []
    additional_output = []
    for unit in report['units']:
        status = unit['status']
        if status in {'cabs_exported', 'lean_elaborated', 'ocaml_core_typed'}:
            continue
        failed_units.append(unit['source'])
        stage = unit.get('stage') or ('lean' if status.startswith('lean_') else 'parser')
        observation = unit.get(stage, {})
        diagnostics = observation.get('diagnostics', '')
        parsed, additional = diagnostic_observations(diagnostics, stage)
        messages = observation.get('diagnostic_messages') or parsed or [status]
        if additional:
            additional_output.append({'source': unit['source'], 'stage': stage, 'lines': additional})
        for index, reason in enumerate(messages):
            key = (stage, status, reason)
            group = groups.setdefault(key, {'stage': stage, 'status': status, 'reason': reason,
                'units': [], 'ssh_units': [], 'first_blocker_units': [], 'first_blocker_ssh_units': [],
                'occurrences': 0, 'occurrences_by_unit': {}, 'examples': []})
            group['occurrences'] += 1
            group['occurrences_by_unit'][unit['source']] = group['occurrences_by_unit'].get(unit['source'], 0) + 1
            if unit['source'] not in group['units']:
                group['units'].append(unit['source'])
                if unit['source'] in priority_units:
                    group['ssh_units'].append(unit['source'])
                group['examples'].append({'source': unit['source'], 'diagnostic': reason})
            if index == 0:
                group['first_blocker_units'].append(unit['source'])
                if unit['source'] in priority_units:
                    group['first_blocker_ssh_units'].append(unit['source'])
    ordered = sorted(groups.values(), key=lambda group: (
        -len(group['first_blocker_ssh_units']), -len(group['first_blocker_units']),
        -len(group['ssh_units']), -len(group['units']), group['reason']))
    for rank, group in enumerate(ordered, 1):
        group.update(rank=rank, affected_units=len(group['units']), affected_ssh_units=len(group['ssh_units']),
                     first_blocker_unit_count=len(group['first_blocker_units']),
                     first_blocker_ssh_unit_count=len(group['first_blocker_ssh_units']))
    return {'recorded_at_utc': report['recorded_at_utc'], 'run_id': report['run_id'],
            'openssh_commit': report['openssh_commit'], 'parser_binary_sha256': report['parser_binary_sha256'],
            'lean_binary_sha256': report['lean_binary_sha256'], 'attempted_units': len(report['units']),
            'whole_build_units': report['whole_build_units'], 'counts': report['counts'],
            'stage_counts': report['stage_counts'], 'semantics_switches': report.get('semantics_switches', []),
            'ssh_linked_units': len(priority_units),
            'ssh_counts': dict(Counter(unit['status'] for unit in report['units'] if unit['source'] in priority_units)),
            'ranking': 'All emitted blockers; first-blocker ssh counts, then first-blocker total, then all affected ssh/total units.',
            'counts_overlap': True, 'unique_failed_units': len(set(failed_units)),
            'diagnostic_occurrences': sum(group['occurrences'] for group in ordered),
            'blockers': ordered, 'additional_failed_run_output': additional_output,
            'limitations': ['Every collected translation error is reported; a TU may appear in multiple groups.',
                            'First-blocker counts are disjoint priority signals. All-affected counts overlap and must not be summed as distinct TUs.',
                            'Failures before translation can prevent later analysis; emitted diagnostics are not a complete inventory of all latent defects.',
                            'Parser export, Lean elaboration, linking, execution, and preservation are different milestones.',
                            'Separate execution/test failures and OS/proof gaps remain in the repair ledgers; this inventory covers import diagnostics.']}


def inventory_markdown(inventory, focused=None):
    def cell(value):
        return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('|', '&#124;').replace('\n', '<br>')
    lines = ['# All emitted import blockers', '',
        'Run `'+inventory['run_id']+'`. Every blocker group and every affected TU are listed below.',
        'First-blocker columns are disjoint. All-affected columns overlap; a TU can have several known blockers.',
        'This reports emitted import diagnostics. Earlier-stage failures can hide later errors. Execution, tests, OS adapters and proof obligations are separate.', '',
        '| Rank | First: all / ssh | All affected: all / ssh | Occurrences | Stage / diagnostic | Affected TUs |',
        '| ---: | ---: | ---: | ---: | --- | --- |']
    for row in inventory['blockers']:
        lines.append('| '+str(row['rank'])+' | '+str(row['first_blocker_unit_count'])+' / '+str(row['first_blocker_ssh_unit_count'])+
            ' | '+str(row['affected_units'])+' / '+str(row['affected_ssh_units'])+' | '+str(row['occurrences'])+
            ' | '+cell(row['stage']+': '+row['reason'])+' | '+', '.join(cell(name) + (' (not rerun)' if 'replayed_units' in inventory and name not in inventory['replayed_units'] else '') for name in row['units'])+' |')
    if inventory.get('additional_failed_run_output'):
        lines += ['', '## Additional failed-run output', '',
                  'These lines are preserved without assuming that warnings or unclassified output are additional blockers.', '',
                  '| TU | Stage | Output |', '| --- | --- | --- |']
        for row in inventory['additional_failed_run_output']:
            lines.append('| '+cell(row['source'])+' | '+cell(row['stage'])+' | '+cell('\n'.join(row['lines']))+' |')
    lines += ['', 'Full per-unit messages, occurrences and original failed stdout/stderr are retained in the matching JSON history.', '']
    baseline = '\n'.join(lines)
    if focused is None:
        return baseline
    current = inventory_markdown(focused).split('\n', 2)[2]
    observed = set(focused['replayed_units'])
    retained = [name for name in focused['baseline_units'] if name not in observed]
    return ('# All emitted import blockers\n\n'
        '## Latest focused OCaml replay\n\n'
        + focused['scope'] + '\n\nReceipt: `' + focused['receipt'] + '`.\n\n'
        + str(len(observed)) + ' TUs rerun; ' + str(len(retained))
        + ' TUs not rerun. The complete Lean results below remain the last checked Lean observations.\n\n'
        + 'Last observed OCaml results: `' + json.dumps(focused['counts'], sort_keys=True) + '`.\n\n'
        + 'Observations matching current maintained sources: ' + str(focused.get('current_source_observations', len(observed)))
        + '; older-source observations: ' + str(focused.get('stale_source_observations', 0)) + '.\n\n'
        + current + '\n## Last complete Lean census (not rerun by this OCaml batch)\n\n'
        + baseline.split('\n', 2)[2]
        + '\n## TUs outside the focused batch: not rerun\n\n'
        + ', '.join(retained) + '\n')


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(argv, cwd, stdout, stderr):
    started = time.monotonic()
    with stdout.open("wb") as out, stderr.open("wb") as err:
        proc = subprocess.Popen(argv, cwd=cwd, stdout=out, stderr=err,
                                env=dict(os.environ, LEAN_ABORT_ON_PANIC="1"),
                                start_new_session=True)
        proc.wait()
        return {"exit_code": proc.returncode, "timed_out": False,
                "elapsed_seconds": round(time.monotonic() - started, 6)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--census", type=Path, required=True)
    parser.add_argument("--cerberus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, help="Publish the latest ranked inventory here and retain history beside it")
    parser.add_argument("--priority-inventory", type=Path, help="Pinned ssh link-closure report from ssh_dependencies.py")
    parser.add_argument("--source", action="append", help="Limit attempts to named units; default all")
    parser.add_argument("--lean", action="store_true", help="Also elaborate imported Cabs to Core in Lean")
    parser.add_argument("--gnu-pointer-conversions", action="store_true",
                        help="Opt in to configured GNU const/signedness pointer conversions; recorded in evidence")
    parser.add_argument("--jobs", type=int, default=12, choices=range(1, 13))
    args = parser.parse_args()
    census = json.loads(args.census.read_text())
    if census["openssh_commit"] != OPENSSH_PIN:
        raise ValueError("Wrong OpenSSH source pin")
    repo = args.cerberus.resolve()
    commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    if commit != CERBERUS_PIN:
        raise ValueError("Wrong Cerberus source pin")
    parser_binary = repo / "_build/default/backend/driver/main.exe"
    lean_binary = repo / "lean_frontend/.lake/build/bin/cerberus-lean"
    runtime = repo / "_build/install/default"
    adapter = Path(__file__).with_name("preprocessed_input.py").resolve()
    # Cerberus splits --cpp on whitespace instead of parsing shell quotation.
    if any(c.isspace() for c in str(adapter) + sys.executable):
        raise ValueError("Cerberus CPP executable and adapter paths must not contain whitespace")
    if not parser_binary.is_file() or (args.lean and not lean_binary.is_file()):
        raise ValueError("Required Cerberus binary has not been built")
    memory_scope = None
    if args.lean:
        self_cgroup = next(line[3:] for line in Path("/proc/self/cgroup").read_text().splitlines()
                           if line.startswith("0::"))
        # Observe the owned scope; no artificial memory cap is required.
        memory_scope = Path("/sys/fs/cgroup") / self_cgroup.lstrip("/")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    selected = set(args.source or [])
    units = [u for u in census["translation_units"] if not selected or u["source"] in selected]
    if args.gnu_pointer_conversions:
        for unit in units:
            flags = unit['preprocessing']['arguments']
            if '-Wno-error=discarded-qualifiers' not in flags or '-Wno-pointer-sign' not in flags:
                raise ValueError('GNU pointer conversion profile is not justified by pinned flags: '+unit['source'])
    if selected - {u["source"] for u in units}:
        raise ValueError("Requested translation units are absent from the census")
    priority_units = set()
    if args.priority_inventory:
        priority = json.loads(args.priority_inventory.read_text())
        if priority["openssh_commit"] != OPENSSH_PIN:
            raise ValueError("Wrong priority inventory source pin")
        priority_units = {unit["source"] for unit in priority["units"]}
        if (len(priority_units) != priority["ssh_linked_unit_count"]
                or not priority_units <= {unit["source"] for unit in census["translation_units"]}):
            raise ValueError("Invalid priority link closure")
        by_source = {unit["source"]: unit for unit in census["translation_units"]}
        for unit in priority["units"]:
            current = by_source[unit["source"]]
            if (unit["source_sha256"] != current["source_sha256"]
                    or unit["preprocessed_sha256"] != current["preprocessing"]["sha256"]):
                raise ValueError("Priority link closure uses different build inputs")

    def attempt(unit):
        row = {"source": unit["source"], "source_sha256": unit["source_sha256"],
               "status": "not_attempted", "executed_in_lean": False,
               "behavioral_equivalence_proved": False}
        pp = unit["preprocessing"]
        if pp["exit_code"] != 0:
            row["status"] = "reference_preprocessing_failed"
            return row
        original = Path(unit["file"])
        source = Path(pp["path"])
        if sha(source) != pp["sha256"] or sha(original) != unit["source_sha256"]:
            raise ValueError(f"Input changed since census: {unit['source']}")
        row["preprocessed_sha256"] = pp["sha256"]
        target = (output / "units" / unit["source"]).with_suffix(".cabs.json")
        target.parent.mkdir(parents=True, exist_ok=True)
        errors = target.with_suffix(".stderr")
        argv = [str(parser_binary), f"--runtime={runtime}", "--cabs-json",
                f"--cpp={sys.executable} {adapter}", str(source)]
        result = run(argv, repo, target, errors)
        row["parser"] = dict(result, arguments=argv, stdout_sha256=sha(target),
                             stderr_sha256=sha(errors), diagnostics=errors.read_text(errors="replace"),
                             stderr_path=str(errors), stdout_path=str(target))
        if result["timed_out"] or result["exit_code"] != 0:
            row['parser']['stdout'] = target.read_text(errors='replace')
            row['parser']['stderr'] = errors.read_text(errors='replace')
            row['parser']['diagnostics'] = '\n'.join(filter(None,
                [row['parser']['stdout'], row['parser']['stderr']]))
            row['parser']['diagnostic_messages'] = diagnostic_messages(row['parser']['diagnostics'], 'parser')
            row["status"] = "c_parser_timeout" if result["timed_out"] else "c_parser_rejected"
            return row
        try:
            tree = json.loads(target.read_text())
        except (UnicodeError, json.JSONDecodeError) as error:
            row.update(status="c_parser_invalid_json", error=str(error))
            return row
        if tree.get("tag") != "TUnit" or not isinstance(tree.get("decls"), list):
            row["status"] = "c_parser_unexpected_schema"
            return row
        row["parser"]["function_definitions"] = sum(d.get("tag") == "EDecl_func" for d in tree["decls"])
        row["parser"]["declarations"] = len(tree["decls"])
        row["status"] = "cabs_exported"
        if args.lean:
            core = target.with_suffix(".core")
            lean_errors = target.with_suffix(".lean.stderr")
            argv = [str(lean_binary), "--pp-core", "--runtime", str(runtime), str(target)]
            if args.gnu_pointer_conversions:
                argv.insert(-1, '--switches=gnu_pointer_conversions')
            result = run(argv, repo, core, lean_errors)
            diagnostic = lean_errors.read_text(errors="replace")
            if result["exit_code"] != 0:
                # --pp-core reports frontend failures on stdout, while native
                # failures and panics can be on stderr. Keep both channels.
                diagnostic = (core.read_text(errors="replace") + "\n" + diagnostic).strip()
            row["lean"] = dict(result, arguments=argv, core_sha256=sha(core),
                               stderr_sha256=sha(lean_errors),
                               diagnostics=diagnostic, stdout_path=str(core), stderr_path=str(lean_errors))
            if result['exit_code'] != 0:
                row['lean']['stdout'] = core.read_text(errors='replace')
                row['lean']['stderr'] = lean_errors.read_text(errors='replace')
                row['lean']['diagnostic_messages'] = diagnostic_messages(diagnostic, 'lean')
            row["status"] = "lean_elaborated" if result["exit_code"] == 0 else (
                "lean_timeout" if result["timed_out"] else "lean_rejected")
        return row

    # Start large inputs first to avoid leaving the slowest unit until the end.
    # Restore census order in the report; every selected unit still runs once.
    scheduled = sorted(units, key=lambda unit: (
        -Path(unit["preprocessing"]["path"]).stat().st_size
        if unit["preprocessing"]["exit_code"] == 0 else 0, unit["source"]))
    sweep_started = time.monotonic()
    completed = {}
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        pending = [pool.submit(attempt, unit) for unit in scheduled]
        for future in as_completed(pending):
            row = future.result()
            completed[row["source"]] = row
            print(json.dumps({"completed": len(completed), "total": len(units),
                              "unit": row["source"], "status": row["status"]}), flush=True)
    results = [completed[unit["source"]] for unit in units]
    execution_profile = {"jobs": args.jobs, "per_unit_deadline_seconds": None,
                         "lean_num_threads": os.environ.get("LEAN_NUM_THREADS"),
                         "elapsed_seconds": round(time.monotonic() - sweep_started, 6)}
    if memory_scope is not None:
        for filename in ("memory.max", "memory.peak", "memory.events", "cpu.stat"):
            path = memory_scope / filename
            execution_profile[filename] = path.read_text().strip() if path.exists() else None
    changed = subprocess.check_output(
        ["git", "-C", str(repo), "diff", "--name-only", "HEAD"], text=True).splitlines()
    untracked = subprocess.check_output(
        ["git", "-C", str(repo), "ls-files", "--others", "--exclude-standard"], text=True).splitlines()
    report = {
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "run_id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"),
        "schema_version": 1, "openssh_commit": OPENSSH_PIN, "cerberus_commit": commit,
        "execution_profile": execution_profile,
        "whole_build_units": len(census["translation_units"]),
        "semantics_switches": ['gnu_pointer_conversions'] if args.gnu_pointer_conversions else [],
        "generator_sha256": sha(__file__), "cpp_adapter_sha256": sha(adapter),
        "census_sha256": sha(args.census), "parser_binary_sha256": sha(parser_binary),
        "lean_binary_sha256": sha(lean_binary) if args.lean else None,
        "cerberus_tracked_changes": changed,
        "cerberus_local_files_sha256": {path: sha(repo / path) if (repo / path).is_file() else None
                                        for path in sorted(set(changed + untracked))},
        "units": results, "counts": dict(Counter(r["status"] for r in results)),
        "limitations": ["The OCaml C parser and its exporter are trusted frontend components.",
                        "A Cabs export is not a Lean import, execution, or preservation theorem.",
                        "Lean elaboration to Core does not exercise system effects or establish equivalence.",
                        "Only the exact preprocessed build inputs listed in the census were attempted."],
        "whole_openssh_executable": False, "whole_openssh_equivalence_proved": False,
    }
    target = output / "import-report.json"
    report["stage_counts"] = {
        "parser_exported": sum("function_definitions" in row.get("parser", {}) for row in results),
        "lean_attempted": sum("lean" in row for row in results),
        "lean_elaborated": sum(row["status"] == "lean_elaborated" for row in results),
    }
    target.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    inventory = blocker_inventory(report, priority_units)
    inventory_path = (args.inventory or (output / "blocker-inventory.json")).resolve()
    inventory_path.parent.mkdir(parents=True, exist_ok=True)
    history = inventory_path.parent / (inventory_path.stem + "-history")
    history.mkdir(parents=True, exist_ok=True)
    history_report = history / (report["run_id"] + ".json")
    with history_report.open("x") as stream:
        json.dump({"inventory": inventory, "report": report}, stream, indent=2, sort_keys=True)
        stream.write("\n")
    inventory["history_report"] = str(history_report)
    temporary = inventory_path.with_name(inventory_path.name + ".tmp-" + report["run_id"])
    temporary.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    temporary.replace(inventory_path)
    inventory_path.with_suffix(".md").write_text(inventory_markdown(inventory), encoding="utf-8")
    print(json.dumps({"units": len(units), "counts": report["counts"], "report": str(target),
                      "inventory": str(inventory_path),
                      "all_blockers": [{key: group[key] for key in ("rank", "stage", "reason", "affected_units", "affected_ssh_units", "first_blocker_unit_count", "first_blocker_ssh_unit_count")}
                                       for group in inventory["blockers"]]}))
    return 0 if all(r["status"] in {"cabs_exported", "lean_elaborated"} for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
