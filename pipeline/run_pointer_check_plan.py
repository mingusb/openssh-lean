"""Sequential orchestration only: existing harnesses remain verification authorities.

Run inside the WSL project after the exact successful build receipt is verified.
No automatic build, retry, fixture change, publication, or parallel execution.
"""
import argparse
import gzip
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from build_guard import workflow_lock, verify_tools, record_child
import subprocess
import sys


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def need(value, message):
    if not value:
        raise RuntimeError(message)


def save(path, value):
    temporary = path.with_suffix(path.suffix+'.tmp')
    temporary.write_text(json.dumps(value, indent=2)+'\n')
    temporary.replace(path)


def check_build(workspace, runtime, expected_hash):
    receipt_path = runtime/'logs/whole-table-build.json'
    need(sha(receipt_path) == expected_hash, 'Build receipt changed or differs from the selected receipt')
    receipt = json.loads(receipt_path.read_text())
    need(receipt['terminal'] is True and receipt['passed'] is True and receipt['exit_code'] == 0,
         'Actual full-build success is required before any engine or binary hash is read')
    need(receipt['inputs_before'] == receipt['inputs_after'], 'Build inputs changed during compilation')
    project = workspace/'outputs/openssh-lean'
    fixed = {'patch': project/'patches/cerberus-gnu-keywords.patch',
             'guard': workspace/'work/build_guard.py',
             'bootstrap': project/'scripts/bootstrap_cerberus.sh',
             'runner': workspace/'work/run_whole_table_build.py',
             'lean_build_runner': project/'scripts/run_capped_lean_build.py',
             'generation_runner': project/'scripts/preserve_generated_timestamps.py',
             'source_manifest': workspace/'work/cerberus-changed-files.txt'}
    for name, path in fixed.items():
        need(sha(path) == receipt['inputs_after'][name], 'Current build input differs: '+name)
    from build_guard import verify_tools
    need(verify_tools() == receipt['inputs_after']['toolchain_lock'], 'Toolchain lock changed after build')
    from native_compiler_cache import identity as native_cache_identity
    need(native_cache_identity(workspace, runtime) == receipt['inputs_after'].get('compiler_cache'),
         'Native compiler cache profile differs from the successful build')
    repo = runtime/'cerberus-lean'
    for name, digest in receipt['inputs_after']['mirrored_source'].items():
        need(sha(repo/name) == digest, 'Mirror source differs: '+name)
        maintained = (workspace/'work/cerberus-lean'/name).read_text(encoding='utf-8').encode()
        need(hashlib.sha256(maintained).hexdigest() == digest, 'Maintained source differs: '+name)
    for name, digest in receipt['outputs'].items():
        need(sha(repo/name) == digest, 'Executable differs from successful build: '+name)
    return receipt


def check_scripts(workspace, plan):
    for step in plan['steps']:
        need(sha(workspace/step['script']) == step['script_sha256'], 'Plan script changed: '+step['id'])
    for name, digest in plan['current_helper_sha256'].items():
        need(sha(workspace/name) == digest, 'Plan helper changed: '+name)


def report_cases(report, groups=None):
    """Normalize the existing case-list and linked-program receipt formats."""
    if isinstance(report.get('cases'), list):
        diagnostics = report.get('diagnostic_cases', [])
        need(isinstance(diagnostics, list), 'Invalid diagnostic case list')
        return report['cases']+diagnostics
    sources = (groups or {}).get('SOURCES')
    if sources and isinstance(report.get('sources'), dict) and set(report['sources']) == set(sources):
        observations = report.get('observations', [])
        labels = {row.get('label') for row in observations if isinstance(row, dict)}
        required = {'native-build-O0', 'native-run-O0', 'native-build-O2', 'native-run-O2',
                    'ocaml', 'object', 'dump', 'lean'} | {Path(name).stem+'-json' for name in sources}
        if required <= labels and report.get('dual_engine_verified') is True:
            return [dict(case='linked-program', passed=report.get('passed'))]
    return []


def complete_report(report, expected_count, groups=None, expected_case_names=None):
    """A harness pass cannot replace missing cases or required interpreter work."""
    cases = report_cases(report, groups)
    # Full runs must contain every inventoried identity exactly once too.
    # Source files describe one linked program, not independent test cases.
    if expected_case_names is None and groups:
        expected_case_names = (['linked-program'] if 'SOURCES' in groups else
                               [name for names in groups.values() for name in names])
    names = [case.get('case', case.get('name')) for case in cases if isinstance(case, dict)]
    exact_names = (expected_case_names is None or
                   (all(isinstance(name, str) for name in names)
                    and len(names) == len(expected_case_names)
                    and len(set(names)) == len(names)
                    and set(names) == set(expected_case_names)))
    return (report.get('passed') is True
            and len(cases) == expected_count
            and exact_names
            and report.get('native_only', False) is False
            and report.get('plan_only', False) is False
            and report.get('artifact_hashes_verified', True) is not False
            and all(isinstance(case, dict) and case.get('passed') is not False for case in cases))


def local_command(step, runtime, workspace):
    command = step['command_argv']
    repo = runtime/'cerberus-lean'
    need(command[:5] == ['env', 'CERB_MEM_MAX=none', 'LEAN_NUM_THREADS=2', str(repo/'scripts/capped'), 'python3'],
         'Unexpected uncapped/two-thread execution policy: '+step['id'])
    need(Path(command[5]).resolve() == workspace/step['script'], 'Unexpected harness path')
    output = Path(command[command.index('--output')+1])
    need(output.parent.resolve() == runtime and output.name not in ('cerberus-lean', 'logs'),
         'Output must be a test-specific direct child of runtime')
    need(not output.is_symlink() and output.resolve() == output, 'Output symlink or path alias refused')
    need(Path(step['result_path']) == output/'result.json', 'Result path differs from command output')
    return command, output


def preserve_previous(output, archive, remaining):
    """Copy only bounded text evidence, then remove this exact old test directory.

    Never traverse or copy a checkout/build tree. Refuse before removal if the
    requested evidence exceeds the limit or any symlink is encountered.
    """
    if not output.exists():
        return remaining
    need(not output.is_symlink() and output.is_dir(), 'Existing output is not an unaliased directory')
    suffixes = {'.json', '.stdout', '.stderr', '.log', '.txt', '.c', '.h', '.core'}
    files = []
    for path in output.rglob('*'):
        need(not path.is_symlink(), 'Symlink in prior test output: '+str(path))
        need(path.name not in ('.git', '_build', '.lake', '_opam'), 'Build tree is not disposable test evidence')
        if path.is_file() and path.suffix in suffixes:
            size = path.stat().st_size
            files.append((path, size))
    # Parser JSON/stdout and embedded reports can contain identical bytes.
    # Charge the fixed uncompressed budget once per distinct payload, while
    # retaining every original path and its independently checked digest.
    payloads = [(path, size, sha(path)) for path, size in files]
    unique = {(size, digest) for _, size, digest in payloads}
    total = sum(size for size, _ in unique)
    logical_total = sum(size for _, size in files)
    need(total <= remaining, 'Prior text evidence exceeds remaining 128MiB batch archive budget')
    archive.mkdir(parents=True, exist_ok=False)
    index = []
    stored = {}
    for index_number, (path, size, digest) in enumerate(payloads):
        key = (size, digest)
        if key in stored:
            need(path.stat().st_size == size and sha(path) == digest,
                 'Prior evidence changed while archiving')
            index.append(dict(stored[key], path=str(path.relative_to(output))))
            continue
        # Oversized text is common with exhaustive outcomes. Compress it under
        # an unambiguous name, retaining the same 128MiB uncompressed budget and
        # 16MiB stored-file ceiling. Verify the complete decoded bytes before
        # removing anything. Compression failure leaves original evidence intact.
        compressed = size > 16*1024**2
        target = archive/('compressed-'+str(index_number)+'.gz') if compressed else archive/'files'/path.relative_to(output)
        target.parent.mkdir(parents=True, exist_ok=True)
        if compressed:
            with path.open('rb') as source, gzip.open(target, 'wb', compresslevel=6) as dest:
                shutil.copyfileobj(source, dest, 1024**2)
            need(target.stat().st_size <= 16*1024**2, 'Compressed evidence exceeds fixed 16MiB stored-file cap')
            with gzip.open(target, 'rb') as stream:
                observed = hashlib.file_digest(stream, 'sha256').hexdigest()
            need(observed == digest, 'Compressed evidence verification failed')
        else:
            shutil.copyfile(path, target)
            need(sha(target) == digest, 'Prior evidence copy failed')
        need(path.stat().st_size == size and sha(path) == digest, 'Prior evidence changed while archiving')
        row = {'path': str(path.relative_to(output)), 'bytes': size, 'sha256': digest,
               'stored_path': str(target.relative_to(archive)), 'encoding': 'gzip' if compressed else 'identity',
               'stored_sha256': sha(target), 'stored_bytes': target.stat().st_size}
        stored[key] = row
        index.append(row)
    # Verify the full source inventory again before deleting any original,
    # including duplicate paths whose content was stored under another name.
    for path, size, digest in payloads:
        need(path.stat().st_size == size and sha(path) == digest,
             'Prior evidence changed while archiving')
    save(archive/'archive-index.json', {'original': str(output), 'files': index,
         'bytes': total, 'logical_bytes': logical_total,
         'deduplicated_bytes': logical_total-total,
         'omitted': 'Compiled test binaries and unrelated non-text artifacts; no build tree copied'})
    # output has already been checked as an exact direct runtime child; symlinks
    # were rejected. Only disposable test artifacts are removed after receipt copy.
    shutil.rmtree(output)
    return remaining-total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, default=Path(__file__).resolve().parents[1] / "local/runtime")
    parser.add_argument('--build-receipt-sha256', required=True)
    parser.add_argument('--run-name', required=True)
    parser.add_argument('--phase', choices=('metadata', 'remaining', 'all'), required=True)
    parser.add_argument('--exclude', action='append', default=[])
    parser.add_argument('--only', action='append', default=[])
    parser.add_argument('--case', action='append', default=[],
                        help='Run selected distinct cases in one compatible harness')
    args = parser.parse_args()
    need(sys.platform == 'linux', 'Run this orchestration in WSL')
    need(re.fullmatch(r'pointer-checks-[a-zA-Z0-9_-]+', args.run_name), 'Invalid run directory name')
    workspace = Path(__file__).resolve().parents[1]
    runtime = args.runtime.resolve()
    plan_path = workspace/'work/pointer-check-plan.json'
    plan_hash = sha(plan_path)
    plan = json.loads(plan_path.read_text())
    check_scripts(workspace, plan)
    build = check_build(workspace, runtime, args.build_receipt_sha256)
    sys.path.insert(0, str(workspace/'outputs/openssh-lean/scripts'))
    from varargs_publication import identity_snapshot
    repo = runtime/'cerberus-lean'
    identity = identity_snapshot(repo)
    selected = [s for s in plan['steps'] if (args.phase == 'all' or
                (s['order'] == 1 if args.phase == 'metadata' else s['order'] != 1))]
    need(not (args.only and args.exclude), 'Choose only or exclude, not both')
    need(set(args.only) <= {s['id'] for s in selected}, 'Unknown/out-of-phase selected suite')
    if args.only:
        args.exclude = [s['id'] for s in selected if s['id'] not in args.only]
    need(set(args.exclude) <= {s['id'] for s in selected}, 'Unknown/out-of-phase excluded suite')
    deferred = [s for s in selected if s['id'] in args.exclude]
    selected = [s for s in selected if s['id'] not in args.exclude]
    expected_case_names = {}
    if args.case:
        need(len(selected) == 1 and len(set(args.case)) == len(args.case),
             'Case selection requires one suite and distinct cases')
        step = selected[0]
        need(step['script'] in {
            'outputs/openssh-lean/scripts/check_gnu_inline_specialization.py',
            'work/check_visible_call_stores.py',
            'work/check_opaque_extent_review.py'},
             'Case selection is not enabled for this harness')
        groups = step.get('case_groups', {})
        for case in args.case:
            owners = [name for name, names in groups.items() if case in names]
            need(len(owners) == 1, 'Unknown or ambiguous case for selected suite: '+case)
        selected_set = set(args.case)
        step = dict(step)
        step['case_groups'] = {
            group: [case for case in names if case in selected_set]
            for group, names in groups.items() if any(case in selected_set for case in names)
        }
        step['expected_case_count'] = len(args.case)
        selected = [step]
        expected_case_names[step['id']] = list(args.case)
    need(bool(selected), 'No suites selected')
    commands = {s['id']: local_command(s, runtime, workspace) for s in selected}
    run = runtime/args.run_name
    run.mkdir(exist_ok=False)
    shutil.copyfile(plan_path, run/'plan.json')
    shutil.copyfile(runtime/'logs/whole-table-build.json', run/'build.json')
    receipt = dict(status='running', pid=os.getpid(), started_utc=now(),
        plan_sha256=plan_hash, runner_sha256=sha(Path(__file__)),
        build_receipt_sha256=args.build_receipt_sha256, build_started_utc=build['started_utc'],
        identity_before=identity, resource_policy={'per_suite_memory':None, 'lean_threads':2, 'concurrency':1},
        selection_scope=('Selected-case diagnostic only; the rest of the suite remains required.'
                         if args.case else 'Complete selected suite inventory.'),
        planned_orders=[s['order'] for s in selected], deferred=[{'order':s['order'], 'id':s['id'],
        'status':'not-selected-still-required'} for s in deferred], completed=[], active=None)
    receipt_path = run/'result.json'
    save(receipt_path, receipt)
    archive_budget = 128*1024**2
    print(json.dumps({'pid':os.getpid(), 'receipt':str(receipt_path), 'orders':receipt['planned_orders']}), flush=True)
    try:
        for step in selected:
            need(sha(plan_path) == plan_hash, 'Plan changed while chain is active')
            check_scripts(workspace, plan)
            check_build(workspace, runtime, args.build_receipt_sha256)
            need(identity_snapshot(repo) == identity, 'Runtime identity changed while chain is active')
            command, output = commands[step['id']]
            if args.case:
                command = command + [argument for case in args.case for argument in ('--case', case)]
            archive_budget = preserve_previous(output, run/'prior'/step['id'], archive_budget)
            stdout, stderr = run/(step['id']+'.stdout'), run/(step['id']+'.stderr')
            row = dict(order=step['order'], id=step['id'], command=command, started_utc=now(),
                       expected_case_count=step['expected_case_count'], output=str(output), terminal=False,
                       expected_case_names=expected_case_names.get(step['id']))
            with stdout.open('wb') as out, stderr.open('wb') as err:
                process = subprocess.Popen(command, stdout=out, stderr=err, cwd=repo)
                record_child(process)
                row['pid'] = process.pid
                receipt['active'] = row
                save(receipt_path, receipt)
                print(json.dumps({'started':step['id'], 'pid':process.pid, 'order':step['order']}), flush=True)
                status = process.wait()
            row.update(terminal=True, exit_code=status, finished_utc=now(),
                       stdout=str(stdout), stderr=str(stderr), stdout_sha256=sha(stdout), stderr_sha256=sha(stderr))
            result_path = Path(step['result_path'])
            row['result_path'] = str(result_path)
            if result_path.is_file():
                row['result_sha256'] = sha(result_path)
                shutil.copyfile(result_path, run/(step['id']+'.result.json'))
                try:
                    report = json.loads(result_path.read_text())
                    row['report_passed'] = report.get('passed')
                    row['required_report_valid'] = complete_report(report, step['expected_case_count'],
                        step.get('case_groups'), expected_case_names.get(step['id']))
                    cases = report_cases(report, step.get('case_groups'))
                    row['cases_count'] = len(cases)
                    row['explicit_failed_cases'] = [case.get('case', case.get('name', '?'))
                        for case in cases if isinstance(case, dict) and case.get('passed') is False]
                except (ValueError, AttributeError, TypeError) as error:
                    row['result_decode_error'] = str(error)
            else:
                row['missing_result'] = True
            row['harness_hash_unchanged'] = sha(workspace/step['script']) == step['script_sha256']
            receipt['completed'].append(row)
            receipt['active'] = None
            save(receipt_path, receipt)
            print(json.dumps({'finished':step['id'], 'exit_code':status,
                              'report_passed':row.get('report_passed'), 'failed':row.get('explicit_failed_cases')}), flush=True)
        check_scripts(workspace, plan)
        check_build(workspace, runtime, args.build_receipt_sha256)
        receipt['identity_after'] = identity_snapshot(repo)
        need(receipt['identity_after'] == identity, 'Final runtime identity changed')
        need(sha(plan_path) == plan_hash, 'Final plan identity changed')
        receipt['status'] = 'terminal'
    except Exception as error:
        receipt['status'] = 'orchestration-failed'
        receipt['error'] = str(error)
    receipt['finished_utc'] = now()
    receipt['all_commands_exit_zero'] = len(receipt['completed']) == len(selected) and all(
        row['exit_code'] == 0 for row in receipt['completed'])
    receipt['all_reports_claim_pass'] = len(receipt['completed']) == len(selected) and all(
        row.get('report_passed') is True for row in receipt['completed'])
    receipt['all_required_reports_valid'] = len(receipt['completed']) == len(selected) and all(
        row.get('required_report_valid') is True for row in receipt['completed'])
    receipt['publication'] = 'Not attempted. Existing publication gates remain authoritative.'
    save(receipt_path, receipt)
    return 0 if receipt['status'] == 'terminal' and receipt['all_commands_exit_zero'] and receipt['all_reports_claim_pass'] and receipt['all_required_reports_valid'] else 1


if __name__ == '__main__':
    with workflow_lock():
        verify_tools()
        raise SystemExit(main())
