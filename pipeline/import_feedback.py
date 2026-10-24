"""Empirical replay of unchanged OpenSSH units after focused compilation.

Selection comes from the complete census. OCaml replay diagnoses the shared
frontend without building a native Lean executable; it never updates that census.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import json
import os
import shlex
from pathlib import Path
import subprocess
import sys
import time

from build_guard import WORKSPACE, RUNTIME, need, save, sha, verify_tools, workflow_lock, PIN

OPENSSH_PIN = 'a8c72b842423f0774f542d3c2197247c3dd28d74'
SCOPE = ('Actual unchanged OpenSSH inputs, OCaml frontend translation and Core typing only. '
         'No Lean execution, complete-census update, regression pass or equivalence claim.')


def resolved_blockers(inventory, blockers=(), sources=()):
    if blockers or sources or not inventory['blockers']:
        return list(blockers)
    # Default to one cause with the largest observed affected cohort. Keep ssh
    # and first-error rank as tie-breakers; never silently sample its TUs.
    best = max(inventory['blockers'], key=lambda row: (
        len(row['units']), len(row.get('ssh_units', [])), -row['rank']))
    return [best['rank']]


def select_units(inventory, census, blockers=(), sources=()):
    """Ranks are resolved against a frozen inventory; overlapping TUs run once."""
    need(inventory['openssh_commit'] == census['openssh_commit'] == OPENSSH_PIN,
         'Replay source pin differs from the pinned release')
    available = {u['source']: u for u in census['translation_units']}
    need(len(available) == len(census['translation_units']), 'Duplicate census units')
    need(set(sources) <= available.keys(), 'Unknown replay translation unit')
    by_rank = {row['rank']: row for row in inventory['blockers']}
    need(set(blockers) <= by_rank.keys(), 'Unknown blocker rank in the current inventory')
    blockers = resolved_blockers(inventory, blockers, sources)
    chosen = set(sources)
    if blockers:
        for rank in blockers:
            chosen.update(by_rank[rank]['units'])
    need(chosen <= available.keys(), 'Blocker inventory names a unit absent from the census')
    return [u for u in census['translation_units'] if u['source'] in chosen]


def selection(workspace, runtime, blockers=(), sources=(), all_units=False, ocaml_cohort=False):
    inventory_path = workspace/'outputs/openssh-lean/evidence/compilation-blockers.json'
    census_path = runtime/'c-import/census.json'
    inventory = json.loads(inventory_path.read_text())
    census = json.loads(census_path.read_text())
    selected_inventory = inventory
    feedback_path = runtime/'logs/latest-focused-import-feedback.json'
    feedback_identity = None
    if ocaml_cohort and feedback_path.is_file():
        feedback = json.loads(feedback_path.read_text())
        if feedback.get('blocker_inventory'):
            path = Path(feedback['blocker_inventory'])
            need(sha(path) == feedback['blocker_inventory_sha256'], 'OCaml blocker inventory changed')
            prior = json.loads(path.read_text())
            if prior.get('baseline_run_id') == inventory['run_id']:
                selected_inventory = prior
                feedback_identity = dict(path=str(path), sha256=sha(path))
    if all_units:
        need(not blockers and not sources, 'All-unit replay cannot silently replace a selected cohort')
        blockers = []
        sources = [u['source'] for u in census['translation_units']]
    else:
        blockers = resolved_blockers(selected_inventory, blockers, sources)
    units = select_units(selected_inventory, census, blockers, sources)
    record = dict(inventory=str(inventory_path), inventory_sha256=sha(inventory_path),
        run_id=inventory['run_id'], census_sha256=sha(census_path),
        blockers=list(blockers), requested_sources=[] if all_units else list(sources),
        all_units=all_units, ocaml_cohort=ocaml_cohort, cohort_inventory=feedback_identity)
    if not units:
        # Runtime-only focused builds have no import replay to establish. Keep
        # the historical input checks below mandatory for every actual replay.
        return [], dict(record, replay_required=False, baseline_statuses={})
    # The historical report establishes which exact input failed. The changed
    # driver may intentionally differ; never require the old executable hash.
    history = inventory_path.parent/'compilation-blockers-history'/(inventory['run_id']+'.json')
    need(history.is_file(), 'Replay baseline report is missing')
    archived = json.loads(history.read_text())
    need(archived['inventory'] == {k:v for k,v in inventory.items() if k != 'history_report'},
         'Replay inventory changed since its preserved baseline')
    report = archived['report']
    need(report['run_id'] == inventory['run_id'] and report['openssh_commit'] == OPENSSH_PIN,
         'Replay baseline does not match its inventory')
    need(report['census_sha256'] == sha(census_path), 'Replay census changed since the baseline')
    baseline = {u['source']: u for u in report['units']}
    for unit in units:
        name = Path(unit['source'])
        need(not name.is_absolute() and '..' not in name.parts, 'Invalid census source path')
        old = baseline.get(unit['source'])
        need(old is not None and old['source_sha256'] == unit['source_sha256'] and
             old.get('preprocessed_sha256') == unit['preprocessing']['sha256'],
             'Replay input differs from the preserved failure: '+unit['source'])
        need(unit['preprocessing']['exit_code'] == 0, 'Replay needs successful pinned preprocessing')
        need(sha(unit['file']) == unit['source_sha256'] and
             sha(unit['preprocessing']['path']) == unit['preprocessing']['sha256'],
             'Pinned replay input bytes changed: '+unit['source'])
        flags = unit['preprocessing']['arguments']
        need('-Wno-error=discarded-qualifiers' in flags and '-Wno-pointer-sign' in flags,
             'GNU pointer profile is not justified by the pinned build')
    return units, dict(record, replay_required=True,
        baseline_report=str(history), baseline_report_sha256=sha(history),
        baseline_statuses={u['source']: baseline[u['source']]['status'] for u in units})


def source_identity(workspace, runtime):
    manifest = workspace/'work/cerberus-changed-files.txt'
    repo = runtime/'cerberus-lean'
    names = manifest.read_text(encoding='utf-8-sig').splitlines()
    original = workspace/'work/cerberus-lean'
    for name in names:
        normalized = (original/name).read_text(encoding='utf-8').encode('utf-8')
        need(hashlib.sha256(normalized).hexdigest() == sha(repo/name), 'Focused source/mirror mismatch: '+name)
    need(subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip() == PIN,
         'Focused mirror has the wrong base')
    return dict(manifest_sha256=sha(manifest),
                patch_sha256=sha(workspace/'outputs/openssh-lean/patches/cerberus-gnu-keywords.patch'),
                sources={name:sha(repo/name) for name in names})


def refresh_table(workspace, receipt, runtime=None):
    """Derive one visible table from immutable receipts, without promoting OCaml."""
    sys.path.insert(0, str(workspace/'outputs/openssh-lean/scripts'))
    from import_c import blocker_inventory, inventory_markdown
    report = json.loads(receipt.read_text())
    need(report.get('terminal') is True and report.get('identity_verified') is True,
         'Cannot publish an incomplete or mismatched focused replay')
    history_path = Path(report['selection']['baseline_report'])
    need(sha(history_path) == report['selection']['baseline_report_sha256'],
         'Focused table baseline changed')
    history = json.loads(history_path.read_text())
    current_path = workspace/'outputs/openssh-lean/evidence/compilation-blockers.json'
    need(sha(current_path) == report['selection']['inventory_sha256'],
         'Focused replay belongs to an older complete census')
    baseline = history['inventory']
    priority = json.loads((workspace/'outputs/openssh-lean/evidence/ssh-dependencies.json').read_text())
    need(priority['openssh_commit'] == OPENSSH_PIN, 'Focused table priority pin differs')
    rows = []
    for unit in report['units']:
        streams = []
        for stream in ['stdout', 'stderr']:
            path = Path(unit[stream+'_path'])
            need(sha(path) == unit[stream+'_sha256'], 'Focused table raw output changed')
            streams.append(path.read_text(encoding='utf-8', errors='replace'))
        rows.append(dict(source=unit['source'], status=unit['status'], stage='ocaml',
                         ocaml=dict(diagnostics='\n'.join(streams))))
    current_names = [u['source'] for u in rows]
    source_key = hashlib.sha256(json.dumps(report['identity_before']['source'],sort_keys=True).encode()).hexdigest()
    for row in rows:
        row.update(observed_source_identity=source_key, observed_receipt=str(receipt))
    previous_rows = []
    feedback_path = runtime/'logs/latest-focused-import-feedback.json' if runtime else None
    if feedback_path and feedback_path.exists():
        previous = json.loads(feedback_path.read_text())
        if previous.get('blocker_inventory'):
            path=Path(previous['blocker_inventory'])
            need(sha(path)==previous['blocker_inventory_sha256'], 'Prior OCaml observations changed')
            prior=json.loads(path.read_text())
            if prior.get('baseline_run_id')==baseline['run_id']:
                previous_rows=prior.get('observed_units',[])
    combined={row['source']:row for row in previous_rows}
    combined.update({row['source']:row for row in rows})
    rows=[combined[u['source']] for u in history['report']['units'] if u['source'] in combined]
    counts={name:sum(u['status']==name for u in rows)
            for name in ['ocaml_core_typed','ocaml_rejected','inconclusive']}
    observations = dict(recorded_at_utc=receipt.parent.parent.name, run_id=receipt.parent.parent.name,
        openssh_commit=OPENSSH_PIN, parser_binary_sha256=baseline['parser_binary_sha256'],
        lean_binary_sha256=None, whole_build_units=baseline['whole_build_units'],
        counts=counts, stage_counts=dict(ocaml_attempted=len(rows)),
        semantics_switches=['gnu_pointer_conversions'], units=rows)
    # Exact changed binary identity remains in the receipt; the baseline parser
    # hash must not imply that the OCaml run used the historical Lean artifact.
    observations['parser_binary_sha256'] = None
    focused = blocker_inventory(observations, {u['source'] for u in priority['units']})
    focused.update(scope=report['scope'], receipt=str(receipt), receipt_sha256=sha(receipt),
                   replayed_units=current_names, observed_units=rows, baseline_run_id=baseline['run_id'],
                   current_source_observations=sum(u['observed_source_identity']==source_key for u in rows),
                   stale_source_observations=sum(u['observed_source_identity']!=source_key for u in rows),
                   baseline_units=[u['source'] for u in history['report']['units']])
    # Derived companion, not a replacement for the immutable operation receipt.
    save(receipt.parent/'blockers.json', focused)
    current_path.with_suffix('.md').write_text(inventory_markdown(baseline, focused), encoding='utf-8')
    return focused


def publish_feedback(workspace, runtime, receipt, lifetime_receipt):
    """Publish derived observations only after the supervisor drains the cohort."""
    report = json.loads(receipt.read_text())
    need(report.get('terminal') is True and report.get('identity_verified') is True,
         'Cannot publish an incomplete or mismatched focused replay')
    lifetime = json.loads(lifetime_receipt.read_text())
    need(lifetime.get('status') == 'cleaned' and
         all(lifetime.get(key) is False for key in
             ('cancelled', 'residual_processes', 'populated')),
         'Cannot publish focused replay before clean process lifetime completion')
    command = lifetime.get('command', [])
    need('--output' in command and command.index('--output')+1 < len(command) and
         Path(command[command.index('--output')+1]) == receipt.parent,
         'Focused process lifetime belongs to another output')
    if report.get('trace'):
        return None
    compact = dict(receipt=str(receipt), receipt_sha256=sha(receipt),
                   scope=SCOPE, required_checks_satisfied=False, **{k:report[k] for k in ['counts','elapsed_seconds','selection']})
    table = refresh_table(workspace, receipt, runtime)
    compact['blocker_groups'] = len(table['blockers'])
    compact['blocker_inventory'] = str(receipt.parent/'blockers.json')
    compact['blocker_inventory_sha256'] = sha(receipt.parent/'blockers.json')
    compact['cumulative_counts'] = table['counts']
    compact['cumulative_ssh_counts'] = table['ssh_counts']
    compact['current_source_observations'] = table['current_source_observations']
    compact['stale_source_observations'] = table['stale_source_observations']
    compact['blocker_table'] = str(workspace/'outputs/openssh-lean/evidence/compilation-blockers.md')
    compact['process_lifetime'] = dict(receipt=str(lifetime_receipt), sha256=sha(lifetime_receipt))
    save(runtime/'logs/latest-focused-import-feedback.json', compact)
    print(json.dumps(compact), flush=True)
    return compact


def replay(workspace, runtime, output, blockers=(), sources=(), all_units=False, ocaml_cohort=False, trace=False):
    from focused_feedback import ocaml_artifact_identity
    need(not trace or (sources and not blockers and not all_units), "Trace requires explicitly selected TUs")
    units, chosen = selection(workspace, runtime, blockers, sources, all_units, ocaml_cohort)
    repo = runtime/'cerberus-lean'
    adapter = workspace/'outputs/openssh-lean/scripts/preprocessed_input.py'
    driver = repo/'_build/default/backend/driver/main.exe'
    def identity():
        return dict(source=source_identity(workspace, runtime), artifacts=ocaml_artifact_identity(repo),
                    helper_sha256=sha(Path(__file__)), adapter_sha256=sha(adapter),
                    tools=verify_tools(),
                    collector_sha256=sha(workspace/'outputs/openssh-lean/scripts/import_c.py'),
                    priority_sha256=sha(workspace/'outputs/openssh-lean/evidence/ssh-dependencies.json'))
    before = identity()
    output.mkdir()
    report = dict(scope=SCOPE, terminal=False, required_checks_satisfied=False,
                  selection=chosen, identity_before=before, jobs=min(12, len(units)),
                  timeout_seconds=None, trace=trace, units=[])
    save(output/'result.json', report)
    print(json.dumps(dict(stage='focused-openssh', selected=len(units),
                          sources=[u['source'] for u in units], receipt=str(output/'result.json'))), flush=True)
    started = time.monotonic()
    def attempt(unit):
        folder = output/'units'/unit['source']
        folder.mkdir(parents=True)
        stdout, stderr = folder/'stdout', folder/'stderr'
        source_view = folder/'input.c'
        source_view.symlink_to(Path(unit['preprocessing']['path']).resolve())
        need(sha(source_view) == unit['preprocessing']['sha256'], 'Replay view changed its input bytes')
        command = [str(driver), '--runtime='+str(repo/'_build/install/default'),
                   '--switches=gnu_pointer_conversions', '--typecheck-core', '--nolibc',
                   '--cpp='+shlex.join([sys.executable, str(adapter), '--preprocessed-link']), str(source_view)]
        if trace:
            command[1:1] = ['--debug=2', '--ast=ail,core', '--pp_flags=loc']
        begun = time.monotonic()
        with stdout.open('wb') as out, stderr.open('wb') as err:
            process = subprocess.Popen(command, cwd=repo, stdout=out, stderr=err)
            process.wait()
        need(source_view.resolve() == Path(unit['preprocessing']['path']).resolve() and
             sha(source_view) == unit['preprocessing']['sha256'], 'Replay view changed while running')
        diagnostic = stderr.read_text(encoding='utf-8', errors='replace')
        setup_failure = process.returncode < 0 or any(message in diagnostic for message in (
            'The file extention is not supported', 'Expected a preprocessed .c symlink',
            'Expected one final .i input', 'error while loading shared libraries'))
        return dict(source=unit['source'], source_sha256=unit['source_sha256'],
            preprocessed_sha256=unit['preprocessing']['sha256'], command=command,
            exit_code=process.returncode, elapsed_seconds=round(time.monotonic()-begun, 3),
            status=('inconclusive' if setup_failure else
                    'ocaml_core_typed' if process.returncode == 0 else 'ocaml_rejected'),
            stdout_path=str(stdout), stderr_path=str(stderr),
            stdout_sha256=sha(stdout), stderr_sha256=sha(stderr))
    completed = {}
    if units:
        with ThreadPoolExecutor(max_workers=report['jobs']) as pool:
            scheduled = sorted(units, key=lambda u: -Path(u['preprocessing']['path']).stat().st_size)
            for future in as_completed([pool.submit(attempt, u) for u in scheduled]):
                row = future.result()
                completed[row['source']] = row
                print(json.dumps(dict(source=row['source'], status=row['status'],
                    elapsed_seconds=row['elapsed_seconds'], completed=len(completed), total=len(units))), flush=True)
    report['units'] = [completed[u['source']] for u in units]
    # Recheck original bytes and selection, as well as compiled-source identity.
    need(selection(workspace, runtime, blockers, sources, all_units, ocaml_cohort) == (units, chosen), 'Replay selection changed while running')
    report['identity_after'] = identity()
    report.update(terminal=True, identity_verified=before == report['identity_after'],
                  elapsed_seconds=round(time.monotonic()-started, 3))
    report['counts'] = {name:sum(u['status']==name for u in report['units'])
                        for name in ['ocaml_core_typed', 'ocaml_rejected', 'inconclusive']}
    save(output/'result.json', report)
    need(report['identity_verified'], 'Replay artifacts changed while running')
    if trace:
        # Traces retain full diagnostics/AIL under their exact receipt, without
        # turning debug messages into blocker groups or replacing the census.
        print(json.dumps(dict(trace_receipt=str(output/'result.json'), counts=report['counts'])), flush=True)
        return report
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--all-units', action='store_true')
    parser.add_argument('--trace', action='store_true')
    parser.add_argument('--ocaml-cohort', action='store_true')
    parser.add_argument('--blocker', type=int, action='append', default=[])
    parser.add_argument('--unit', action='append', default=[])
    args = parser.parse_args()
    sys.path.insert(0, str(WORKSPACE/'outputs/openssh-lean/scripts'))
    need(os.environ.get('OPENSSH_LEAN_LOCK_TOKEN'), 'Focused replay must join the checked workflow')
    with workflow_lock():
        result = replay(WORKSPACE, RUNTIME, args.output, args.blocker, args.unit, args.all_units, args.ocaml_cohort, args.trace)
    return 1 if result['counts']['ocaml_rejected'] or result['counts']['inconclusive'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
